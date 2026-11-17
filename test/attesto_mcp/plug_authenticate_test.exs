defmodule AttestoMCP.Plug.AuthenticateTest do
  @moduledoc false
  use ExUnit.Case, async: false

  import Plug.Conn
  import Plug.Test

  alias Anubis.Server.Frame
  alias Attesto.Plug.OAuthError
  alias Attesto.StepUp.Requirement
  alias AttestoMCP.Plug.Authenticate
  alias AttestoMCP.Test.DPoPReplay
  alias AttestoMCP.Test.Factory

  doctest Authenticate, only: [dpop_target_uri: 2]

  setup do
    %{config: Factory.config()}
  end

  test "Authenticate advertises challenge scopes only when configured", %{config: config} do
    request = conn(:post, "/mcp")
    default = Factory.authenticate(request, config)
    assert default.status == 401
    assert [challenge] = get_resp_header(default, "www-authenticate")
    refute challenge =~ "scope="

    scopes = ["tools.call"]
    opts = Authenticate.init(config: config, resource_audience: Factory.htu(), challenge_scopes: scopes)
    assert opts[:challenge_scopes] == scopes

    configured = Authenticate.call(request, opts)
    assert configured.status == 401
    assert [configured_challenge] = get_resp_header(configured, "www-authenticate")

    reference = OAuthError.missing_credentials(request, challenge_scopes: scopes)
    assert [reference_challenge] = get_resp_header(reference, "www-authenticate")
    assert Regex.scan(~r/\bscope="[^"]*"/, configured_challenge) == Regex.scan(~r/\bscope="[^"]*"/, reference_challenge)
  end

  describe "Streamable HTTP Origin validation" do
    test "accepts a normalized pinned or listed origin behind a proxy", %{config: config} do
      token = Factory.access_token(config)

      for origin <- ["https://mcp.example", "HTTP://CLIENT.example:80", "http://[::1]:4000"] do
        response =
          :post
          |> conn("http://proxy.internal:8080/mcp")
          |> put_req_header("authorization", "Bearer " <> token)
          |> put_req_header("origin", origin)
          |> Factory.authenticate(config,
            base_url: "HTTPS://MCP.example:443/prefix",
            allowed_origins: ["http://client.example", "http://[::1]:4000"]
          )

        refute response.halted
      end
    end

    test "refuses foreign, malformed, duplicate, and null origins", %{config: config} do
      invalid_origins = [
        ["https://foreign.example"],
        ["https://mcp.example/"],
        ["https://mcp.example:65536"],
        ["https://mcp.example:"],
        ["https://user@mcp.example"],
        ["https://mcp.example?x"],
        ["https://mcp.example#x"],
        ["https://mcp.example, https://foreign.example"],
        ["https://mcp.example https://foreign.example"],
        ["https://mcp.example", "https://mcp.example"],
        ["null"]
      ]

      for values <- invalid_origins do
        request = %{conn(:post, "/mcp") | req_headers: Enum.map(values, &{"origin", &1})}
        response = Factory.authenticate(request, config, base_url: "https://mcp.example")
        assert_forbidden_origin(response)
      end
    end

    test "an unpinned mount trusts only the allowlist when Origin is present", %{config: config} do
      request =
        :post
        |> conn("https://mcp.example/mcp")
        |> put_req_header("authorization", "Bearer " <> Factory.access_token(config))

      refute Factory.authenticate(request, config).halted

      origin_request = put_req_header(request, "origin", "https://mcp.example")
      assert_forbidden_origin(Factory.authenticate(origin_request, config))
      refute Factory.authenticate(origin_request, config, allowed_origins: ["https://mcp.example"]).halted
    end

    test "dynamic mode derives the expected origin only from an allowed Host", %{config: config} do
      opts = [allow_dynamic_origin: true, allowed_hosts: ["localhost:4000"]]
      token = Factory.access_token(config)

      for host <- ["localhost:4000", "localhost:4001", "rebound.example:4000"] do
        origin = "http://" <> host

        response =
          :post
          |> conn(origin <> "/mcp")
          |> put_req_header("authorization", "Bearer " <> token)
          |> put_req_header("origin", origin)
          |> Factory.authenticate(config, opts)

        if host == "localhost:4000", do: refute(response.halted), else: assert_forbidden_origin(response)
      end
    end

    test "validates the configured allowlist at initialization", %{config: config} do
      for invalid <- [nil, "https://mcp.example", [42], ["null"], ["file://host"], ["https://mcp.example/"]] do
        assert_raise ArgumentError, ~r/:allowed_origins/, fn ->
          Authenticate.init(config: config, resource_audience: Factory.htu(), allowed_origins: invalid)
        end
      end
    end

    test "a failing pinned-origin resolver refuses without disclosing the failure", %{config: config} do
      response =
        :post
        |> conn("https://mcp.example/mcp")
        |> put_req_header("origin", "https://mcp.example")
        |> Factory.authenticate(config, base_url: fn _conn -> raise "private callback failure" end)

      assert_forbidden_origin(response)
    end

    defp assert_forbidden_origin(response) do
      assert response.halted
      assert response.status == 403
      assert response.resp_body == "forbidden origin"
      assert ["no-store"] == get_resp_header(response, "cache-control")
      assert [] == get_resp_header(response, "www-authenticate")
    end
  end

  describe "DPoP target URI with a pinned origin" do
    setup %{config: config} do
      jwk = Factory.dpop_jwk()
      %{jwk: jwk, token: Factory.access_token(config, dpop_jkt: Factory.dpop_jkt(jwk))}
    end

    test "refuses a proof made for the server named in the request Host", %{
      config: config,
      jwk: jwk,
      token: token
    } do
      conn =
        "https://other.example/mcp"
        |> dpop_request(token, jwk, "https://other.example/mcp")
        |> pinned_authenticate(config, base_url: "https://mcp.example")

      assert_dpop_refused(conn)
    end

    test "accepts a proof for the pinned origin when the request Host differs", %{
      config: config,
      jwk: jwk,
      token: token
    } do
      conn =
        "http://other.example:4000/mcp"
        |> dpop_request(token, jwk, "https://mcp.example/mcp")
        |> pinned_authenticate(config, base_url: "https://mcp.example")

      refute conn.halted
      assert conn.assigns.attesto_mcp_sender == %{binding: :dpop, jkt: Factory.dpop_jkt(jwk)}
    end

    test "pins the target URI from an :origin callback", %{config: config, jwk: jwk, token: token} do
      opts = [origin: {__MODULE__, :pinned_origin}]

      refused =
        "https://other.example/mcp"
        |> dpop_request(token, jwk, "https://other.example/mcp")
        |> pinned_authenticate(config, opts)

      assert_dpop_refused(refused)

      accepted =
        "https://other.example/mcp"
        |> dpop_request(token, jwk, "https://mcp.example/mcp")
        |> pinned_authenticate(config, opts)

      refute accepted.halted
    end

    test "joins a path-prefixed base_url with the request path", %{config: config, jwk: jwk, token: token} do
      opts = [base_url: "https://mcp.example/tools"]

      refused =
        "https://other.example/mcp"
        |> dpop_request(token, jwk, "https://other.example/mcp")
        |> pinned_authenticate(config, opts)

      assert_dpop_refused(refused)

      accepted =
        "http://10.0.0.5/mcp"
        |> dpop_request(token, jwk, "https://mcp.example/tools/mcp")
        |> pinned_authenticate(config, opts)

      refute accepted.halted
    end

    test "resolves an http development origin only under allow_http" do
      request = conn(:post, "http://127.0.0.1:4000/mcp")

      assert Authenticate.dpop_target_uri(request, base_url: "http://localhost:4000", allow_http: true) ==
               "http://localhost:4000/mcp"

      assert_raise ArgumentError, ~r/:base_url/, fn ->
        Authenticate.dpop_target_uri(request, base_url: "http://localhost:4000")
      end
    end

    test "accepts loopback HTTP DPoP proofs only under allow_http and refuses non-loopback HTTP pins at init",
         %{config: config, jwk: jwk, token: token} do
      loopback_opts = [base_url: "http://localhost:4000", allow_http: true]

      accepted =
        "http://127.0.0.1:4000/mcp"
        |> dpop_request(token, jwk, "http://localhost:4000/mcp", allow_http: true)
        |> pinned_authenticate(config, loopback_opts)

      refute accepted.halted

      refused =
        "http://127.0.0.1:4000/mcp"
        |> dpop_request(token, jwk, "http://localhost:4000/mcp", allow_http: true)
        |> pinned_authenticate(config, base_url: "https://mcp.example", allow_http: true)

      assert_dpop_refused(refused)

      assert_raise ArgumentError, ~r/HTTPS or loopback HTTP/, fn ->
        Authenticate.init(
          config: config,
          resource_audience: Factory.htu(),
          replay_check: DPoPReplay.callback(),
          base_url: "http://mcp.example",
          allow_http: true
        )
      end
    end

    test "an explicit :htu takes precedence over the pinned origin", %{config: config, jwk: jwk, token: token} do
      opts = [base_url: "https://mcp.example", htu: &Factory.htu/1]

      refused =
        "https://mcp.example/mcp"
        |> dpop_request(token, jwk, "https://mcp.example/mcp")
        |> pinned_authenticate(config, opts)

      assert_dpop_refused(refused)

      accepted =
        "https://mcp.example/mcp"
        |> dpop_request(token, jwk, Factory.htu())
        |> pinned_authenticate(config, opts)

      refute accepted.halted
    end

    test "refuses malformed :htu values at init instead of discarding the pin", %{config: config} do
      for bad_htu <- ["https://mcp.example/mcp", {Factory, :htu}, nil] do
        assert_raise ArgumentError, ~r/:htu must be a 1-arity function/, fn ->
          Authenticate.init(
            config: config,
            resource_audience: Factory.htu(),
            replay_check: DPoPReplay.callback(),
            base_url: "https://mcp.example",
            htu: bad_htu
          )
        end
      end
    end

    test "requires a pinned origin, :htu, or allow_dynamic_origin with :allowed_hosts for DPoP mounts", %{
      config: config
    } do
      assert_raise ArgumentError, ~r/accepts DPoP requires/, fn ->
        Authenticate.init(
          config: config,
          resource_audience: Factory.htu(),
          replay_check: DPoPReplay.callback()
        )
      end

      assert_raise ArgumentError, ~r/:allowed_hosts/, fn ->
        Authenticate.init(
          config: config,
          resource_audience: Factory.htu(),
          replay_check: DPoPReplay.callback(),
          allow_dynamic_origin: true
        )
      end

      bearer_only = Authenticate.init(config: config, resource_audience: Factory.htu())
      assert Keyword.fetch!(bearer_only, :bearer_methods) == [:header]
    end

    test "allow_dynamic_origin with :allowed_hosts admits listed hosts and refuses others", %{
      config: config,
      jwk: jwk,
      token: token
    } do
      opts =
        Authenticate.init(
          config: config,
          resource_audience: Factory.htu(),
          replay_check: DPoPReplay.callback(),
          allow_dynamic_origin: true,
          allowed_hosts: ["mcp.example"]
        )

      allowed =
        "https://mcp.example/mcp"
        |> dpop_request(token, jwk, "https://mcp.example/mcp")
        |> Authenticate.call(opts)

      refute allowed.halted

      denied =
        "https://other.example/mcp"
        |> dpop_request(token, jwk, "https://other.example/mcp")
        |> Authenticate.call(opts)

      assert denied.halted
      assert denied.status == 401

      assert Authenticate.host_allowed?(
               %{host: "::1", port: 4000},
               [" [::1]:4000 "]
             )
    end
  end

  def pinned_origin(_conn), do: "https://mcp.example"

  defp dpop_request(url, token, jwk, htu, proof_opts \\ []) do
    {proof, _jkt} = Factory.dpop_proof(token, Keyword.merge([jwk: jwk, htu: htu], proof_opts))

    # Plug.Test takes the request host (the `Host` header) from the URL.
    :post
    |> conn(url)
    |> put_req_header("authorization", "DPoP " <> token)
    |> put_req_header("dpop", proof)
  end

  defp pinned_authenticate(conn, config, opts) do
    opts = Keyword.merge([config: config, resource_audience: Factory.htu(), replay_check: DPoPReplay.callback()], opts)
    Authenticate.call(conn, Authenticate.init(opts))
  end

  defp assert_dpop_refused(conn) do
    assert conn.halted
    assert conn.status == 401
    assert JSON.decode!(conn.resp_body)["error"] == "invalid_dpop_proof"
    assert ["DPoP " <> _] = get_resp_header(conn, "www-authenticate")
  end

  test "bearer token is accepted when unbound", %{config: config} do
    token = Factory.access_token(config)

    conn =
      :post
      |> conn("/mcp")
      |> put_req_header("authorization", "Bearer " <> token)
      |> Factory.authenticate(config)

    refute conn.halted
    assert conn.assigns.attesto_mcp_claims["sub"] == "usr_123"
    assert conn.assigns.attesto_mcp_scopes == [AttestoMCP.Scopes.tools_call()]
    assert conn.assigns.attesto_mcp_sender == %{binding: :bearer}
  end

  test "form-body access_token is rejected by default", %{config: config} do
    token = Factory.access_token(config)

    conn =
      %{"access_token" => token}
      |> Factory.form_post()
      |> Factory.authenticate(config)

    assert conn.halted
    assert conn.status == 401
    assert JSON.decode!(conn.resp_body)["error"] == "invalid_token"
  end

  test "form-body access_token is accepted only when the body bearer method is enabled", %{
    config: config
  } do
    token = Factory.access_token(config)

    conn =
      %{"access_token" => token}
      |> Factory.form_post()
      |> Factory.authenticate(config, bearer_methods: [:header, :body])

    refute conn.halted
    assert conn.assigns.attesto_mcp_claims["sub"] == "usr_123"
    assert conn.assigns.attesto_mcp_sender == %{binding: :bearer}
  end

  test "assigns the canonical :attesto_context, which the Anubis bridge projects", %{config: config} do
    token = Factory.access_token(config)

    conn =
      :post
      |> conn("/mcp")
      |> put_req_header("authorization", "Bearer " <> token)
      |> Factory.authenticate(config)

    ctx = conn.assigns.attesto_context
    assert ctx.subject == "usr_123"
    assert ctx.client_id == "client-1"
    assert ctx.scope == [AttestoMCP.Scopes.tools_call()]
    assert ctx.claims["sub"] == "usr_123"
    assert ctx.cnf == nil
    assert ctx.principal == nil

    # End-to-end: the Anubis transport copies conn.assigns into frame.assigns, so
    # the bridge projects the real plug output into frame.context.auth. (This is
    # the path a manually-constructed :attesto_context in the bridge unit tests
    # cannot cover.)
    frame = Frame.new(conn.assigns)
    auth = AttestoMCP.Anubis.put_auth(frame).context.auth
    assert auth.sub == "usr_123"
    assert auth.client_id == "client-1"
    assert auth.scope == AttestoMCP.Scopes.tools_call()
    assert auth.scopes == [AttestoMCP.Scopes.tools_call()]
  end

  test "DPoP-bound token is rejected as bearer", %{config: config} do
    jwk = Factory.dpop_jwk()
    jkt = Factory.dpop_jkt(jwk)
    token = Factory.access_token(config, dpop_jkt: jkt)

    conn =
      :post
      |> conn("/mcp")
      |> put_req_header("authorization", "Bearer " <> token)
      |> Factory.authenticate(config)

    assert conn.halted
    assert conn.status == 401
    assert [%{"error" => "invalid_token"}] = [JSON.decode!(conn.resp_body)]
    assert ["DPoP " <> _] = get_resp_header(conn, "www-authenticate")
  end

  test "DPoP-bound token is accepted with a valid proof", %{config: config} do
    jwk = Factory.dpop_jwk()
    jkt = Factory.dpop_jkt(jwk)
    token = Factory.access_token(config, dpop_jkt: jkt)
    {proof, ^jkt} = Factory.dpop_proof(token, jwk: jwk)

    conn =
      :post
      |> conn("/mcp")
      |> put_req_header("authorization", "DPoP " <> token)
      |> put_req_header("dpop", proof)
      |> Factory.authenticate(config, replay_check: DPoPReplay.callback())

    refute conn.halted
    assert conn.assigns.attesto_mcp_sender == %{binding: :dpop, jkt: jkt}
  end

  test "mTLS-bound token is rejected without matching certificate context", %{config: config} do
    der = Factory.self_signed_cert_der()
    {:ok, thumbprint} = Attesto.MTLS.compute_thumbprint(der)
    token = Factory.access_token(config, mtls_cert_thumbprint: thumbprint)

    conn =
      :post
      |> conn("/mcp")
      |> put_req_header("authorization", "Bearer " <> token)
      |> Factory.authenticate(config)

    assert conn.halted
    assert conn.status == 401
    assert JSON.decode!(conn.resp_body)["error"] == "invalid_token"
  end

  test "principal callback is called with verified claims and sender context", %{config: config} do
    token = Factory.access_token(config)
    parent = self()

    principal = fn claims, sender ->
      send(parent, {:principal, claims["sub"], sender})
      {:ok, %{subject: claims["sub"]}}
    end

    conn =
      :post
      |> conn("/mcp")
      |> put_req_header("authorization", "Bearer " <> token)
      |> Factory.authenticate(config, principal: principal)

    refute conn.halted
    assert conn.assigns.attesto_mcp_principal == %{subject: "usr_123"}
    assert_receive {:principal, "usr_123", %{binding: :bearer}}
  end

  test "a nil principal is assigned explicitly so a prior session value is cleared", %{config: config} do
    token = Factory.access_token(config)

    conn =
      :post
      |> conn("/mcp")
      |> assign(:attesto_mcp_principal, %{stale: true})
      |> put_req_header("authorization", "Bearer " <> token)
      |> Factory.authenticate(config, principal: fn _claims, _sender -> {:ok, nil} end)

    refute conn.halted
    assert Map.has_key?(conn.assigns, :attesto_mcp_principal)
    assert conn.assigns.attesto_mcp_principal == nil
  end

  test "every malformed principal callback result is a generic 401", %{config: config} do
    token = Factory.access_token(config)

    for result <- [:error, nil, :unexpected, {:error, "private detail"}, {:ok}] do
      conn =
        :post
        |> conn("/mcp")
        |> put_req_header("authorization", "Bearer " <> token)
        |> Factory.authenticate(config, principal: fn _claims, _sender -> result end)

      assert conn.halted
      assert conn.status == 401
      assert JSON.decode!(conn.resp_body)["error"] == "invalid_token"
      refute conn.resp_body =~ "private detail"
    end
  end

  test "custom error renderer is used", %{config: config} do
    send_error = fn conn, status, body ->
      conn
      |> put_resp_content_type("application/vnd.example.auth+json")
      |> send_resp(status, JSON.encode!(%{"oauth" => body}))
      |> halt()
    end

    conn =
      :post
      |> conn("/mcp")
      |> Factory.authenticate(config, send_error: send_error)

    assert conn.halted
    assert conn.status == 401
    assert JSON.decode!(conn.resp_body)["oauth"]["error"] == "invalid_token"
    assert ["application/vnd.example.auth+json" <> _] = get_resp_header(conn, "content-type")
  end

  test "resource metadata URL is added to challenges", %{config: config} do
    conn =
      :post
      |> conn("/mcp")
      |> Factory.authenticate(config,
        resource_metadata_url: "https://mcp.example.com/.well-known/oauth-protected-resource/mcp"
      )

    assert conn.halted
    assert [challenge] = get_resp_header(conn, "www-authenticate")
    assert challenge =~ "resource_metadata="
  end

  test "resource metadata URL can be derived from the protected MCP path", %{config: config} do
    conn =
      :post
      |> conn("https://mcp.example.com/mcp/user")
      |> Factory.authenticate(config, resource_path: "/mcp/user")

    assert conn.halted
    assert [challenge] = get_resp_header(conn, "www-authenticate")
    assert challenge =~ ~s(resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp/user")
  end

  test "blank resource metadata URL fails during initialization", %{config: config} do
    assert_raise ArgumentError, ~r/:resource_metadata_url/, fn ->
      Authenticate.init(config: config, resource_audience: Factory.htu(), resource_metadata_url: "")
    end

    assert_raise ArgumentError, ~r/:resource_metadata_url/, fn ->
      Authenticate.init(
        config: config,
        resource_audience: Factory.htu(),
        resource_metadata_url: "",
        resource_path: "/mcp"
      )
    end
  end

  test "invalid resource metadata callback values fall back safely", %{config: config} do
    for invalid <- [nil, "", 123, %{}] do
      with_path =
        :post
        |> conn("https://mcp.example.com/mcp")
        |> Factory.authenticate(config,
          resource_metadata_url: fn _conn -> invalid end,
          resource_path: "/mcp"
        )

      assert [challenge] = get_resp_header(with_path, "www-authenticate")
      assert challenge =~ ~s(resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp")

      without_path =
        :post
        |> conn("https://mcp.example.com/mcp")
        |> Factory.authenticate(config, resource_metadata_url: fn _conn -> invalid end)

      assert [challenge] = get_resp_header(without_path, "www-authenticate")
      refute challenge =~ "resource_metadata="
    end

    via_mfa =
      :post
      |> conn("https://mcp.example.com/mcp")
      |> Factory.authenticate(config,
        resource_metadata_url: {__MODULE__, :metadata_url_result, [nil]},
        resource_path: "/mcp"
      )

    assert [challenge] = get_resp_header(via_mfa, "www-authenticate")
    assert challenge =~ ~s(resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp")
  end

  test "unsafe resource metadata callback URLs use a validated fallback", %{config: config} do
    unsafe_urls = [
      "javascript:alert(1)",
      "https://user:pass@mcp.example.com/metadata",
      "https://mcp.example.com/metadata#fragment",
      "https://mcp.example.com/%ZZ",
      "http://localhost:4000/.well-known/oauth-protected-resource/mcp"
    ]

    for unsafe <- unsafe_urls do
      conn =
        :post
        |> conn("https://mcp.example.com/mcp")
        |> Factory.authenticate(config,
          resource_metadata_url: fn _conn -> unsafe end,
          resource_path: "/mcp"
        )

      assert [challenge] = get_resp_header(conn, "www-authenticate")
      assert challenge =~ ~s(resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp")
    end
  end

  test "HTTP resource metadata requires an explicit development opt-in", %{config: config} do
    conn =
      :post
      |> conn("http://localhost:4000/mcp")
      |> Factory.authenticate(config,
        resource_metadata_url: fn _conn ->
          "http://localhost:4000/.well-known/oauth-protected-resource/mcp"
        end,
        allow_http: true
      )

    assert [challenge] = get_resp_header(conn, "www-authenticate")
    assert challenge =~ ~s(resource_metadata="http://localhost:4000/.well-known/oauth-protected-resource/mcp")
  end

  test "HTTP opt-in is preserved by the derived metadata resolver", %{config: config} do
    conn =
      :post
      |> conn("http://localhost:4000/mcp")
      |> Factory.authenticate(config,
        resource_path: "/mcp",
        base_url: "http://localhost:4000",
        allow_http: true
      )

    assert [challenge] = get_resp_header(conn, "www-authenticate")
    assert challenge =~ ~s(resource_metadata="http://localhost:4000/.well-known/oauth-protected-resource/mcp")
  end

  test "direct authentication enforces a literal resource audience", %{config: config} do
    resource = "https://mcp.example.com/mcp/reports"
    token = Factory.access_token(config, audience: resource)

    conn =
      :post
      |> conn("/mcp/reports")
      |> put_req_header("authorization", "Bearer " <> token)
      |> Factory.authenticate(config, resource_audience: resource)

    refute conn.halted
    assert conn.assigns.attesto_mcp_claims["aud"] == resource
  end

  test "direct authentication passes through a core-only trusted audience policy", %{config: config} do
    resource = "https://mcp.example.com/mcp/reports"
    token = Factory.access_token(config, audience: resource)

    conn =
      :post
      |> conn("/mcp/reports")
      |> put_req_header("authorization", "Bearer " <> token)
      |> Factory.authenticate(config, trusted_audiences: [resource])

    refute conn.halted
    assert conn.assigns.attesto_mcp_claims["aud"] == resource
  end

  test "resource_metadata_url accepts an {module, fun} tuple", %{config: config} do
    conn =
      :post
      |> conn("https://mcp.example.com/mcp")
      |> Factory.authenticate(config, resource_metadata_url: {__MODULE__, :metadata_url})

    assert conn.halted
    assert [challenge] = get_resp_header(conn, "www-authenticate")
    assert challenge =~ ~s(resource_metadata="https://pinned.example/.well-known/oauth-protected-resource/mcp")
  end

  test "the 2.x metadata challenge compatibility helper remains callable" do
    metadata_www_authenticate = Function.capture(Authenticate, :metadata_www_authenticate, 1)

    callback =
      metadata_www_authenticate.(
        resource_metadata_url: "https://mcp.example.com/.well-known/oauth-protected-resource/mcp"
      )

    conn = callback.(conn(:get, "https://mcp.example.com/mcp"), "Bearer")

    assert get_resp_header(conn, "www-authenticate") == [
             ~s(Bearer, resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp")
           ]

    assert metadata_www_authenticate.(www_authenticate: fn conn, _ -> conn end) == nil
  end

  test "hidden 2.x metadata option and fallback helpers remain callable" do
    opts =
      Authenticate.oauth_error_metadata_opts(
        resource_metadata_url: "https://mcp.example.com/metadata",
        allow_http: true
      )

    assert opts == [allow_http: true, resource_metadata: "https://mcp.example.com/metadata"]
    assert Authenticate.oauth_error_metadata_opts(www_authenticate: fn conn, _ -> conn end) == []

    request = conn(:get, "https://mcp.example.com/mcp")
    blank = fn _conn -> "" end
    valid = fn _conn -> "https://mcp.example.com/custom" end

    assert Authenticate.resolve_resource_metadata_url(request, valid, "fallback") ==
             "https://mcp.example.com/custom"

    assert Authenticate.resolve_resource_metadata_url(request, blank, "fallback") == "fallback"
  end

  def metadata_url(_conn), do: "https://pinned.example/.well-known/oauth-protected-resource/mcp"
  def metadata_url_result(_conn, result), do: result

  test "a custom :www_authenticate is a total override - the generated resource_metadata is suppressed", %{
    config: config
  } do
    conn =
      :post
      |> conn("https://mcp.example.com/mcp/user")
      |> Factory.authenticate(config,
        resource_path: "/mcp/user",
        resource_metadata_url: fn _conn -> raise "metadata callback must not run" end,
        www_authenticate: fn conn, _challenge ->
          Plug.Conn.put_resp_header(conn, "www-authenticate", "Custom realm=x")
        end
      )

    assert conn.halted
    assert ["Custom realm=x"] = get_resp_header(conn, "www-authenticate")
  end

  test "assigns stay protocol-shaped" do
    assign_names = [:attesto_mcp_claims, :attesto_mcp_principal, :attesto_mcp_scopes, :attesto_mcp_sender]

    assert Enum.all?(assign_names, &String.starts_with?(Atom.to_string(&1), "attesto_mcp_"))
  end

  test "init/1 is escape-safe, so the plug works as a compile-time pipeline plug" do
    # init/1 must bake no closure: under plug_init_mode: :compile its result is
    # embedded via Macro.escape, which rejects anonymous functions. The generated
    # resource_metadata challenge is built in call/2, never in init/1.
    opts = [
      config: &Factory.config/0,
      resource_audience: :resource,
      resource_path: "/mcp",
      base_url: "https://mcp.example.com"
    ]

    assert opts |> Authenticate.init() |> Macro.escape()
  end

  test "init/1 preserves options normalized by the core plug" do
    opts =
      Authenticate.init(
        config: &Factory.config/0,
        resource_audience: Factory.htu(),
        resource_path: "/mcp",
        step_up: [acr_values: ["phr"], max_age: 300]
      )

    assert Keyword.fetch!(opts, :step_up) ==
             %Requirement{acr_values: ["phr"], max_age: 300}

    assert Keyword.fetch!(opts, :bearer_methods) == [:header]
    assert Keyword.fetch!(opts, :resource_path) == "/mcp"
  end
end
