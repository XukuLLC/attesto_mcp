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
    test "accepts a token audienced to this resource's identifier", %{config: config} do
      # config.audience is "https://mcp.example.com/mcp"; pinning the origin makes
      # the derived resource identifier equal it.
      token = Factory.access_token(config, scopes: [Scopes.tools_call()])

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
      assert conn.assigns.attesto_mcp_claims["sub"] == "usr_123"
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

  defp form_post(params) do
    :post
    |> conn("/mcp", params)
    |> put_req_header("content-type", "application/x-www-form-urlencoded")
  end
end
