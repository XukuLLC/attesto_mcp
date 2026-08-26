defmodule AttestoMCP.Plug.ProtectResourceTest do
  @moduledoc false
  use ExUnit.Case, async: false

  import Plug.Conn
  import Plug.Test

  alias AttestoMCP.Plug.ProtectResource
  alias AttestoMCP.Scopes
  alias AttestoMCP.Test.DPoPReplay
  alias AttestoMCP.Test.Factory

  setup do
    %{config: Factory.config()}
  end

  test "bearer token with the required scope is accepted", %{config: config} do
    token = Factory.access_token(config, scopes: [Scopes.tools_call()])

    conn =
      :post
      |> conn("/mcp")
      |> put_req_header("authorization", "Bearer " <> token)
      |> protect(config, scopes: [Scopes.tools_call()])

    refute conn.halted
    assert conn.assigns.attesto_mcp_claims["sub"] == "usr_123"
    assert conn.assigns.attesto_mcp_scopes == [Scopes.tools_call()]
  end

  describe "RFC 8707 / RFC 9728 per-resource audience confinement" do
    test "accepts a scalar token audience matching this resource's identifier", %{config: config} do
      resource = "https://mcp.example.com/mcp/reports"

      token =
        Factory.access_token(config,
          audience: resource,
          scopes: [Scopes.tools_call()]
        )

      conn =
        :post
        |> conn("/mcp/reports")
        |> put_req_header("authorization", "Bearer " <> token)
        |> protect(config,
          scopes: [Scopes.tools_call()],
          resource: "/mcp/reports",
          base_url: "https://mcp.example.com",
          resource_audience: :resource
        )

      refute conn.halted
      assert conn.assigns.attesto_mcp_claims["sub"] == "usr_123"
      assert conn.assigns.attesto_mcp_claims["aud"] == resource
    end

    test "rejects a token audienced to a sibling resource", %{config: config} do
      # A token minted for a DIFFERENT resource than the one this plug guards.
      sibling = %{config | audience: "https://mcp.example.com/admin"}
      token = Factory.access_token(sibling, scopes: [Scopes.tools_call()])

      conn =
        :post
        |> conn("/mcp")
        |> put_req_header("authorization", "Bearer " <> token)
        |> protect(config,
          scopes: [Scopes.tools_call()],
          resource: "/mcp",
          base_url: "https://mcp.example.com",
          resource_audience: :resource
        )

      assert conn.halted
      assert conn.status == 401
      assert JSON.decode!(conn.resp_body)["error"] == "invalid_token"
    end

    test "rejects an audience array containing this resource and an untrusted sibling", %{config: config} do
      resource = "https://mcp.example.com/mcp"
      sibling = "https://mcp.example.com/admin"

      token =
        Factory.access_token(config,
          audience: [resource, sibling],
          scopes: [Scopes.tools_call()]
        )

      conn =
        :post
        |> conn("/mcp")
        |> put_req_header("authorization", "Bearer " <> token)
        |> protect(config,
          scopes: [Scopes.tools_call()],
          resource: "/mcp",
          base_url: "https://mcp.example.com",
          resource_audience: :resource
        )

      assert conn.halted
      assert conn.status == 401
      assert JSON.decode!(conn.resp_body)["error"] == "invalid_token"
    end

    test "accepts an array whose members all exactly match this resource", %{config: config} do
      resource = "https://mcp.example.com/mcp"

      token =
        config
        |> Factory.access_token(scopes: [Scopes.tools_call()])
        |> replace_audience(config, [resource, resource])

      conn =
        :post
        |> conn("/mcp")
        |> put_req_header("authorization", "Bearer " <> token)
        |> protect(config,
          scopes: [Scopes.tools_call()],
          resource: "/mcp",
          base_url: "https://mcp.example.com",
          resource_audience: :resource
        )

      refute conn.halted
      assert conn.assigns.attesto_mcp_claims["aud"] == [resource, resource]
    end

    test "rejects conflicting route and core audience policies at initialization", %{config: config} do
      assert_raise ArgumentError, ~r/:resource_audience and :trusted_audiences are mutually exclusive/, fn ->
        ProtectResource.init(
          config: config,
          scopes: [Scopes.tools_call()],
          resource: "/mcp",
          resource_audience: :resource,
          trusted_audiences: ["https://mcp.example.com/admin"]
        )
      end
    end

    test "rejects a derived resource audience without a resource path at initialization", %{config: config} do
      assert_raise ArgumentError, ~r/requires a :resource \/ :resource_path option/, fn ->
        ProtectResource.init(
          config: config,
          scopes: [Scopes.tools_call()],
          resource_audience: :resource
        )
      end
    end

    test "rejects malformed resource audience policy forms at initialization", %{config: config} do
      for malformed <- [:resourse, fn -> config.audience end, ""] do
        assert_raise ArgumentError, ~r/:resource_audience must be/, fn ->
          ProtectResource.init(
            config: config,
            scopes: [Scopes.tools_call()],
            resource: "/mcp",
            resource_audience: malformed
          )
        end
      end
    end

    test "allows a core-only trusted audience policy when route derivation is explicitly disabled", %{config: config} do
      resource = "https://mcp.example.com/mcp/reports"

      token =
        Factory.access_token(config,
          audience: resource,
          scopes: [Scopes.tools_call()]
        )

      conn =
        :post
        |> conn("/mcp/reports")
        |> put_req_header("authorization", "Bearer " <> token)
        |> protect(config,
          scopes: [Scopes.tools_call()],
          resource: "/mcp/reports",
          resource_audience: false,
          trusted_audiences: [resource]
        )

      refute conn.halted
      assert conn.assigns.attesto_mcp_claims["aud"] == resource
    end

    test "supports literal, function, and MFA resource audience callbacks", %{config: config} do
      resource = "https://mcp.example.com/mcp/reports"
      token = Factory.access_token(config, audience: resource, scopes: [Scopes.tools_call()])
      Process.put({__MODULE__, :resource_audience}, resource)

      resource_audiences = [
        resource,
        fn _conn -> resource end,
        {__MODULE__, :resource_audience_from_process},
        {__MODULE__, :resource_audience_from_argument, [resource]}
      ]

      for resource_audience <- resource_audiences do
        conn =
          :post
          |> conn("/mcp/reports")
          |> put_req_header("authorization", "Bearer " <> token)
          |> protect(config,
            scopes: [Scopes.tools_call()],
            resource: "/mcp/reports",
            resource_audience: resource_audience
          )

        refute conn.halted
        assert conn.assigns.attesto_mcp_claims["aud"] == resource
      end
    end

    test "a resource audience callback returning nil fails closed", %{config: config} do
      token = Factory.access_token(config, scopes: [Scopes.tools_call()])

      conn =
        :post
        |> conn("/mcp")
        |> put_req_header("authorization", "Bearer " <> token)
        |> protect(config,
          scopes: [Scopes.tools_call()],
          resource: "/mcp",
          resource_audience: fn _conn -> nil end
        )

      assert conn.halted
      assert conn.status == 401
      assert JSON.decode!(conn.resp_body)["error"] == "invalid_token"
    end

    test "rejects the configured default audience when it is not this resource", %{config: config} do
      token = Factory.access_token(config, scopes: [Scopes.tools_call()])

      conn =
        :post
        |> conn("/mcp/reports")
        |> put_req_header("authorization", "Bearer " <> token)
        |> protect(config,
          scopes: [Scopes.tools_call()],
          resource: "/mcp/reports",
          base_url: "https://mcp.example.com",
          resource_audience: :resource
        )

      assert conn.halted
      assert conn.status == 401
      assert JSON.decode!(conn.resp_body)["error"] == "invalid_token"
    end

    test "supports two- and three-element MFA config callbacks", %{config: config} do
      resource = "https://mcp.example.com/mcp/reports"
      token = Factory.access_token(config, audience: resource, scopes: [Scopes.tools_call()])
      Process.put({__MODULE__, :config}, config)

      config_callbacks = [
        {__MODULE__, :config_from_process},
        {__MODULE__, :config_from_argument, [config]}
      ]

      for config_callback <- config_callbacks do
        conn =
          :post
          |> conn("/mcp/reports")
          |> put_req_header("authorization", "Bearer " <> token)
          |> protect(config,
            config: config_callback,
            scopes: [Scopes.tools_call()],
            resource: "/mcp/reports",
            base_url: "https://mcp.example.com",
            resource_audience: :resource
          )

        refute conn.halted
        assert conn.assigns.attesto_mcp_claims["aud"] == resource
      end
    end

    test "without :resource_audience the host's global config.audience is used", %{config: config} do
      # Backward compatible: a token audienced to the global config.audience is
      # accepted (no per-resource override).
      token = Factory.access_token(config, scopes: [Scopes.tools_call()])

      conn =
        :post
        |> conn("/mcp")
        |> put_req_header("authorization", "Bearer " <> token)
        |> protect(config, scopes: [Scopes.tools_call()], resource: "/mcp")

      refute conn.halted
    end
  end

  describe "RFC 9470 step-up (:step_up passthrough)" do
    test "a token meeting the acr requirement is admitted", %{config: config} do
      now = System.system_time(:second)
      token = Factory.access_token(config, scopes: [Scopes.tools_call()], acr: "phr", auth_time: now)

      conn =
        :post
        |> conn("/mcp")
        |> put_req_header("authorization", "Bearer " <> token)
        |> protect(config, scopes: [Scopes.tools_call()], step_up: [acr_values: ["phr"], max_age: 300])

      refute conn.halted
    end

    test "an acr-less token is challenged with insufficient_user_authentication", %{config: config} do
      token = Factory.access_token(config, scopes: [Scopes.tools_call()])

      conn =
        :post
        |> conn("/mcp")
        |> put_req_header("authorization", "Bearer " <> token)
        |> protect(config, scopes: [Scopes.tools_call()], step_up: [acr_values: ["phr"]])

      assert conn.halted
      assert conn.status == 401
      assert JSON.decode!(conn.resp_body)["error"] == "insufficient_user_authentication"
      [challenge] = Plug.Conn.get_resp_header(conn, "www-authenticate")
      assert challenge =~ ~s(acr_values="phr")
    end
  end

  test "form-body access_token is rejected by default", %{config: config} do
    token = Factory.access_token(config, scopes: [Scopes.tools_call()])

    conn =
      %{"access_token" => token}
      |> form_post()
      |> protect(config, scopes: [Scopes.tools_call()])

    assert conn.halted
    assert conn.status == 401
    assert JSON.decode!(conn.resp_body)["error"] == "invalid_token"
  end

  test "passes bearer_methods through to Authenticate", %{config: config} do
    token = Factory.access_token(config, scopes: [Scopes.tools_call()])

    conn =
      %{"access_token" => token}
      |> form_post()
      |> protect(config, scopes: [Scopes.tools_call()], bearer_methods: [:header, :body])

    refute conn.halted
    assert conn.assigns.attesto_mcp_claims["sub"] == "usr_123"
  end

  test "a token missing the required scope is rejected with insufficient_scope", %{config: config} do
    token = Factory.access_token(config, scopes: [Scopes.resources_read()])

    conn =
      :post
      |> conn("/mcp")
      |> put_req_header("authorization", "Bearer " <> token)
      |> protect(config, scopes: [Scopes.tools_call()])

    assert conn.halted
    assert conn.status == 403
    assert JSON.decode!(conn.resp_body)["error"] == "insufficient_scope"
  end

  test "scope enforcement is skipped once authentication halts", %{config: config} do
    token = Factory.access_token(config, dpop_jkt: dpop_jkt())

    conn =
      :post
      |> conn("/mcp")
      |> put_req_header("authorization", "Bearer " <> token)
      |> protect(config, scopes: [Scopes.tools_call()])

    assert conn.halted
    assert conn.status == 401
    assert JSON.decode!(conn.resp_body)["error"] == "invalid_token"
  end

  test "a DPoP-bound token is accepted with a valid proof", %{config: config} do
    jwk = Factory.dpop_jwk()
    {_unused, jkt} = Factory.dpop_proof("placeholder", jwk: jwk)
    token = Factory.access_token(config, dpop_jkt: jkt, scopes: [Scopes.tools_call()])
    {proof, ^jkt} = Factory.dpop_proof(token, jwk: jwk)

    conn =
      :post
      |> conn("/mcp")
      |> put_req_header("authorization", "DPoP " <> token)
      |> put_req_header("dpop", proof)
      |> protect(config, scopes: [Scopes.tools_call()], replay_check: DPoPReplay.callback())

    refute conn.halted
    assert conn.assigns.attesto_mcp_sender == %{binding: :dpop, jkt: jkt}
  end

  test "the resource path drives the RFC 9728 resource_metadata challenge", %{config: config} do
    conn =
      :post
      |> conn("https://mcp.example.com/mcp/brokers")
      |> protect(config, scopes: [Scopes.tools_call()], resource: "/mcp/brokers")

    assert conn.halted
    assert [challenge] = get_resp_header(conn, "www-authenticate")
    assert challenge =~ ~s(resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp/brokers")
  end

  test "a pinned :base_url drives the challenge URL over the request host", %{config: config} do
    # Simulate a TLS-terminating proxy: the conn arrives http on an internal
    # host. The pinned origin must drive the resource_metadata URL so a client
    # cannot be steered to a spoofed metadata location.
    conn =
      :post
      |> conn("http://10.0.0.5/mcp/brokers")
      |> protect(config,
        scopes: [Scopes.tools_call()],
        resource: "/mcp/brokers",
        base_url: "https://mcp.example.com"
      )

    assert conn.halted
    assert [challenge] = get_resp_header(conn, "www-authenticate")
    assert challenge =~ ~s(resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp/brokers")
  end

  test "an insufficient_scope 403 carries the resource_metadata pointer when the resource is pinned", %{
    config: config
  } do
    token = Factory.access_token(config, scopes: [Scopes.resources_read()])

    conn =
      :post
      |> conn("http://10.0.0.5/mcp/brokers")
      |> put_req_header("authorization", "Bearer " <> token)
      |> protect(config,
        scopes: [Scopes.tools_call()],
        resource: "/mcp/brokers",
        base_url: "https://mcp.example.com"
      )

    assert conn.status == 403
    assert JSON.decode!(conn.resp_body)["error"] == "insufficient_scope"
    assert [challenge] = get_resp_header(conn, "www-authenticate")
    assert challenge =~ ~s(resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp/brokers")
  end

  test "a principal-callback rejection 401 carries the resource_metadata pointer", %{config: config} do
    token = Factory.access_token(config, scopes: [Scopes.tools_call()])

    conn =
      :post
      |> conn("http://10.0.0.5/mcp/brokers")
      |> put_req_header("authorization", "Bearer " <> token)
      |> protect(config,
        scopes: [Scopes.tools_call()],
        resource: "/mcp/brokers",
        base_url: "https://mcp.example.com",
        principal: fn _claims, _sender -> {:error, :rejected} end
      )

    assert conn.status == 401
    assert JSON.decode!(conn.resp_body)["error"] == "invalid_token"
    assert [challenge] = get_resp_header(conn, "www-authenticate")
    assert challenge =~ ~s(resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp/brokers")
  end

  test "a host :www_authenticate overrides the generated resource_metadata on a scope rejection", %{
    config: config
  } do
    token = Factory.access_token(config, scopes: [Scopes.resources_read()])

    conn =
      :post
      |> conn("https://mcp.example.com/mcp/brokers")
      |> put_req_header("authorization", "Bearer " <> token)
      |> protect(config,
        scopes: [Scopes.tools_call()],
        resource: "/mcp/brokers",
        www_authenticate: fn c, _challenge -> put_resp_header(c, "www-authenticate", "Custom realm=x") end
      )

    assert conn.status == 403
    # The host's total override wins; the generated resource_metadata is not applied.
    assert ["Custom realm=x"] = get_resp_header(conn, "www-authenticate")
  end

  test "the single required scope is accepted via :scope", %{config: config} do
    token = Factory.access_token(config, scopes: [Scopes.tools_call()])

    conn =
      :post
      |> conn("/mcp")
      |> put_req_header("authorization", "Bearer " <> token)
      |> protect(config, scope: Scopes.tools_call())

    refute conn.halted
  end

  describe "dynamic scope boundary" do
    test "authenticates once and authorizes a scope selected after classification", %{config: config} do
      token = Factory.access_token(config, scopes: [Scopes.tools_call()])
      protection = dynamic_protection(config)

      conn =
        :post
        |> conn("/mcp")
        |> put_req_header("authorization", "Bearer " <> token)
        |> ProtectResource.authenticate(protection)
        |> ProtectResource.authorize(protection, [Scopes.tools_call()])

      refute conn.halted
      assert conn.assigns.attesto_mcp_claims["sub"] == "usr_123"
      assert conn.assigns.attesto_mcp_scopes == [Scopes.tools_call()]
    end

    test "rejects a dynamically selected scope the authenticated token lacks", %{config: config} do
      token = Factory.access_token(config, scopes: [Scopes.resources_read()])
      protection = dynamic_protection(config)

      conn =
        :post
        |> conn("/mcp")
        |> put_req_header("authorization", "Bearer " <> token)
        |> ProtectResource.authenticate(protection)
        |> ProtectResource.authorize(protection, [Scopes.tools_call()])

      assert conn.halted
      assert conn.status == 403
      assert JSON.decode!(conn.resp_body)["error"] == "insufficient_scope"
    end

    test "halts on authentication failure before dynamic authorization", %{config: config} do
      protection = dynamic_protection(config)

      conn =
        :post
        |> conn("/mcp")
        |> ProtectResource.authenticate(protection)
        |> ProtectResource.authorize(protection, [Scopes.tools_call()])

      assert conn.halted
      assert conn.status == 401
      assert JSON.decode!(conn.resp_body)["error"] == "invalid_token"
    end

    test "an empty dynamic scope list still requires successful authentication", %{config: config} do
      token = Factory.access_token(config, scopes: [])
      protection = dynamic_protection(config)

      authenticated =
        :post
        |> conn("/mcp")
        |> put_req_header("authorization", "Bearer " <> token)
        |> ProtectResource.authenticate(protection)
        |> ProtectResource.authorize(protection, [])

      refute authenticated.halted

      unauthenticated =
        :post
        |> conn("/mcp")
        |> ProtectResource.authorize(protection, [])

      assert unauthenticated.halted
      assert unauthenticated.status == 401
      assert JSON.decode!(unauthenticated.resp_body)["error"] == "invalid_token"
    end

    test "pre-existing assigns cannot bypass the prepared authentication boundary", %{config: config} do
      protection =
        ProtectResource.prepare(
          config: config,
          htu: fn _conn -> Factory.htu() end,
          resource: "/mcp",
          scopes_key: :custom_scopes
        )

      conn =
        :post
        |> conn("/mcp")
        |> assign(:custom_scopes, [Scopes.tools_call()])
        |> assign(:attesto_mcp_claims, %{"sub" => "unverified"})
        |> ProtectResource.authorize(protection, [Scopes.tools_call()])

      assert conn.halted
      assert conn.status == 401
      assert JSON.decode!(conn.resp_body)["error"] == "invalid_token"
    end

    test "authentication by one prepared boundary cannot authorize another", %{config: config} do
      token = Factory.access_token(config, scopes: [Scopes.tools_call()])
      boundary_a = dynamic_protection(config)

      boundary_b =
        ProtectResource.prepare(
          config: config,
          htu: fn _conn -> Factory.htu() end,
          resource: "/mcp",
          step_up: [acr_values: ["phr"]]
        )

      conn =
        :post
        |> conn("/mcp")
        |> put_req_header("authorization", "Bearer " <> token)
        |> ProtectResource.authenticate(boundary_a)
        |> ProtectResource.authorize(boundary_b, [Scopes.tools_call()])

      assert conn.halted
      assert conn.status == 401
      assert JSON.decode!(conn.resp_body)["error"] == "invalid_token"
    end

    test "a later authentication call clears an earlier prepared-boundary binding", %{config: config} do
      token = Factory.access_token(config, scopes: [Scopes.tools_call()])
      prepared = dynamic_protection(config)

      static =
        ProtectResource.init(
          config: config,
          htu: fn _conn -> Factory.htu() end,
          resource: "/mcp",
          scopes: [Scopes.tools_call()]
        )

      conn =
        :post
        |> conn("/mcp")
        |> put_req_header("authorization", "Bearer " <> token)
        |> ProtectResource.authenticate(prepared)
        |> ProtectResource.authenticate(static)
        |> ProtectResource.authorize(prepared, [Scopes.tools_call()])

      assert conn.halted
      assert conn.status == 401
      assert JSON.decode!(conn.resp_body)["error"] == "invalid_token"
    end

    test "rejects invalid RFC 6749 dynamic scope tokens before rendering headers", %{config: config} do
      token = Factory.access_token(config, scopes: [Scopes.resources_read()])
      protection = dynamic_protection(config)

      authenticated =
        :post
        |> conn("/mcp")
        |> put_req_header("authorization", "Bearer " <> token)
        |> ProtectResource.authenticate(protection)

      malformed = [
        "tools call",
        ~s(tools"call),
        "tools\\call",
        "tools\tcall",
        "tools\r\ncall",
        <<0>>,
        "café"
      ]

      for scope <- malformed do
        assert_raise ArgumentError, ~r/RFC 6749 scope-token/, fn ->
          ProtectResource.authorize(authenticated, protection, [scope])
        end
      end
    end

    test "dynamic DPoP authentication verifies the proof only once", %{config: config} do
      jwk = Factory.dpop_jwk()
      {_unused, jkt} = Factory.dpop_proof("placeholder", jwk: jwk)
      token = Factory.access_token(config, dpop_jkt: jkt, scopes: [Scopes.tools_call()])
      {proof, ^jkt} = Factory.dpop_proof(token, jwk: jwk)
      protection = dynamic_protection(config, replay_check: DPoPReplay.callback())

      conn =
        :post
        |> conn("/mcp")
        |> put_req_header("authorization", "DPoP " <> token)
        |> put_req_header("dpop", proof)
        |> ProtectResource.authenticate(protection)
        |> ProtectResource.authorize(protection, [Scopes.tools_call()])

      refute conn.halted
      assert conn.assigns.attesto_mcp_sender == %{binding: :dpop, jkt: jkt}
    end

    test "dynamic scope rejection carries the pinned metadata challenge", %{config: config} do
      protection =
        dynamic_protection(config,
          base_url: "https://mcp.example.com",
          resource_audience: :resource
        )

      token =
        Factory.access_token(config,
          audience: "https://mcp.example.com/mcp",
          scopes: [Scopes.resources_read()]
        )

      conn =
        :post
        |> conn("http://10.0.0.5/mcp")
        |> put_req_header("authorization", "Bearer " <> token)
        |> ProtectResource.authenticate(protection)
        |> ProtectResource.authorize(protection, [Scopes.tools_call()])

      assert conn.halted
      assert conn.status == 403
      assert JSON.decode!(conn.resp_body)["error"] == "insufficient_scope"
      assert [challenge] = get_resp_header(conn, "www-authenticate")
      assert challenge =~ ~s(resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp")
      assert challenge =~ ~s(scope="mcp:tools:call")
    end

    test "rejects ambiguous or malformed dynamic boundary use", %{config: config} do
      protection = dynamic_protection(config)

      assert_raise ArgumentError, ~r/must call authenticate\/2 and authorize\/3/, fn ->
        ProtectResource.call(conn(:post, "/mcp"), protection)
      end

      assert_raise ArgumentError, ~r/accepts dynamic scopes only/, fn ->
        ProtectResource.prepare(config: config, scopes: [Scopes.tools_call()])
      end

      for malformed <- [[""], [Scopes.tools_call(), Scopes.tools_call()], [:tools], "mcp:tools:call"] do
        assert_raise ArgumentError, ~r/dynamic scopes must be/, fn ->
          ProtectResource.authorize(conn(:post, "/mcp"), protection, malformed)
        end
      end
    end

    test "prepare/1 is escape-safe" do
      opts = [
        config: &Factory.config/0,
        resource: "/mcp",
        base_url: "https://mcp.example.com"
      ]

      assert opts |> ProtectResource.prepare() |> Macro.escape()
    end
  end

  test "init/1 is escape-safe, so the plug works as a compile-time router pipeline plug" do
    # `plug_init_mode: :compile` (the prod / Phoenix router default) embeds the
    # `init/1` result via `Macro.escape`, which rejects closures. A generated
    # `resource_metadata` challenge must therefore be built at call time, never
    # baked into init - otherwise the router carrying this plug will not compile.
    opts = [
      config: &Factory.config/0,
      resource: "/mcp",
      scopes: [Scopes.tools_call()],
      base_url: "https://mcp.example.com"
    ]

    # The precise failure mode: escaping the init result must not raise.
    assert opts |> ProtectResource.init() |> Macro.escape()
  end

  test "compiles inside a Plug.Builder pipeline under init_mode: :compile" do
    defmodule CompiledMCPPipeline do
      @moduledoc false
      use Plug.Builder, init_mode: :compile

      plug ProtectResource,
        config: &Factory.config/0,
        resource: "/mcp",
        scopes: ["mcp:tools:call"],
        base_url: "https://mcp.example.com"
    end

    # If init/1 baked a closure the defmodule above would have raised at compile
    # time; reaching here (with a usable plug) proves the compile-mode wiring.
    assert function_exported?(CompiledMCPPipeline, :call, 2)
  end

  defp dpop_jkt do
    {_proof, jkt} = Factory.dpop_proof("placeholder")
    jkt
  end

  def config_from_process, do: Process.get({__MODULE__, :config})
  def config_from_argument(config), do: config
  def resource_audience_from_process(_conn), do: Process.get({__MODULE__, :resource_audience})
  def resource_audience_from_argument(_conn, resource), do: resource

  defp replace_audience(token, config, audience) do
    {:ok, claims} = Attesto.Token.peek_signed_claims(config, token)
    header = token |> JOSE.JWS.peek_protected() |> JSON.decode!()
    key = config.keystore.signing_pem() |> JOSE.JWK.from_pem()
    signed = JOSE.JWT.sign(key, header, Map.put(claims, "aud", audience))
    {_jws, compact} = JOSE.JWS.compact(signed)
    compact
  end

  defp protect(conn, config, opts) do
    opts =
      Keyword.merge(
        [
          config: config,
          htu: fn _conn -> Factory.htu() end
        ],
        opts
      )

    ProtectResource.call(conn, ProtectResource.init(opts))
  end

  defp dynamic_protection(config, opts \\ []) do
    ProtectResource.prepare(
      Keyword.merge(
        [
          config: config,
          htu: fn _conn -> Factory.htu() end,
          resource: "/mcp"
        ],
        opts
      )
    )
  end

  defp form_post(params) do
    :post
    |> conn("/mcp", params)
    |> put_req_header("content-type", "application/x-www-form-urlencoded")
  end
end
