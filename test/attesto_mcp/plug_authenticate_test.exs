defmodule AttestoMCP.Plug.AuthenticateTest do
  @moduledoc false
  use ExUnit.Case, async: false

  import Plug.Conn
  import Plug.Test

  alias Anubis.Server.Frame
  alias AttestoMCP.Plug.Authenticate
  alias AttestoMCP.Test.DPoPReplay
  alias AttestoMCP.Test.Factory

  setup do
    %{config: Factory.config()}
  end

  test "bearer token is accepted when unbound", %{config: config} do
    token = Factory.access_token(config)

    conn =
      :post
      |> conn("/mcp")
      |> put_req_header("authorization", "Bearer " <> token)
      |> authenticate(config)

    refute conn.halted
    assert conn.assigns.attesto_mcp_claims["sub"] == "usr_123"
    assert conn.assigns.attesto_mcp_scopes == [AttestoMCP.Scopes.tools_call()]
    assert conn.assigns.attesto_mcp_sender == %{binding: :bearer}
  end

  test "form-body access_token is rejected by default", %{config: config} do
    token = Factory.access_token(config)

    conn =
      %{"access_token" => token}
      |> form_post()
      |> authenticate(config)

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
      |> form_post()
      |> authenticate(config, bearer_methods: [:header, :body])

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
      |> authenticate(config)

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
    {_proof, jkt} = Factory.dpop_proof("placeholder", jwk: jwk)
    token = Factory.access_token(config, dpop_jkt: jkt)

    conn =
      :post
      |> conn("/mcp")
      |> put_req_header("authorization", "Bearer " <> token)
      |> authenticate(config)

    assert conn.halted
    assert conn.status == 401
    assert [%{"error" => "invalid_token"}] = [JSON.decode!(conn.resp_body)]
    assert ["DPoP " <> _] = get_resp_header(conn, "www-authenticate")
  end

  test "DPoP-bound token is accepted with a valid proof", %{config: config} do
    jwk = Factory.dpop_jwk()
    {_unused, jkt} = Factory.dpop_proof("placeholder", jwk: jwk)
    token = Factory.access_token(config, dpop_jkt: jkt)
    {proof, ^jkt} = Factory.dpop_proof(token, jwk: jwk)

    conn =
      :post
      |> conn("/mcp")
      |> put_req_header("authorization", "DPoP " <> token)
      |> put_req_header("dpop", proof)
      |> authenticate(config, replay_check: DPoPReplay.callback())

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
      |> authenticate(config)

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
      |> authenticate(config, principal: principal)

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
      |> authenticate(config, principal: fn _claims, _sender -> {:ok, nil} end)

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
        |> authenticate(config, principal: fn _claims, _sender -> result end)

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
      |> authenticate(config, send_error: send_error)

    assert conn.halted
    assert conn.status == 401
    assert JSON.decode!(conn.resp_body)["oauth"]["error"] == "invalid_token"
    assert ["application/vnd.example.auth+json" <> _] = get_resp_header(conn, "content-type")
  end

  test "resource metadata URL is added to challenges", %{config: config} do
    conn =
      :post
      |> conn("/mcp")
      |> authenticate(config,
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
      |> authenticate(config, resource_path: "/mcp/user")

    assert conn.halted
    assert [challenge] = get_resp_header(conn, "www-authenticate")
    assert challenge =~ ~s(resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp/user")
  end

  test "blank resource metadata URL is absent unless a resource path can derive it", %{config: config} do
    without_path =
      :post
      |> conn("https://mcp.example.com/mcp")
      |> authenticate(config, resource_metadata_url: "")

    assert [challenge] = get_resp_header(without_path, "www-authenticate")
    refute challenge =~ "resource_metadata="

    with_path =
      :post
      |> conn("https://mcp.example.com/mcp")
      |> authenticate(config, resource_metadata_url: "", resource_path: "/mcp")

    assert [challenge] = get_resp_header(with_path, "www-authenticate")
    assert challenge =~ ~s(resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp")
  end

  test "invalid resource metadata callback values fall back safely", %{config: config} do
    for invalid <- [nil, "", 123, %{}] do
      with_path =
        :post
        |> conn("https://mcp.example.com/mcp")
        |> authenticate(config,
          resource_metadata_url: fn _conn -> invalid end,
          resource_path: "/mcp"
        )

      assert [challenge] = get_resp_header(with_path, "www-authenticate")
      assert challenge =~ ~s(resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp")

      without_path =
        :post
        |> conn("https://mcp.example.com/mcp")
        |> authenticate(config, resource_metadata_url: fn _conn -> invalid end)

      assert [challenge] = get_resp_header(without_path, "www-authenticate")
      refute challenge =~ "resource_metadata="
    end

    via_mfa =
      :post
      |> conn("https://mcp.example.com/mcp")
      |> authenticate(config,
        resource_metadata_url: {__MODULE__, :metadata_url_result, [nil]},
        resource_path: "/mcp"
      )

    assert [challenge] = get_resp_header(via_mfa, "www-authenticate")
    assert challenge =~ ~s(resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp")
  end

  test "direct authentication enforces a literal resource audience", %{config: config} do
    resource = "https://mcp.example.com/mcp/reports"
    token = Factory.access_token(config, audience: resource)

    conn =
      :post
      |> conn("/mcp/reports")
      |> put_req_header("authorization", "Bearer " <> token)
      |> authenticate(config, resource_audience: resource)

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
      |> authenticate(config, trusted_audiences: [resource])

    refute conn.halted
    assert conn.assigns.attesto_mcp_claims["aud"] == resource
  end

  test "resource_metadata_url accepts an {module, fun} tuple", %{config: config} do
    conn =
      :post
      |> conn("https://mcp.example.com/mcp")
      |> authenticate(config, resource_metadata_url: {__MODULE__, :metadata_url})

    assert conn.halted
    assert [challenge] = get_resp_header(conn, "www-authenticate")
    assert challenge =~ ~s(resource_metadata="https://pinned.example/.well-known/oauth-protected-resource/mcp")
  end

  def metadata_url(_conn), do: "https://pinned.example/.well-known/oauth-protected-resource/mcp"
  def metadata_url_result(_conn, result), do: result

  test "a custom :www_authenticate is a total override - the generated resource_metadata is suppressed", %{
    config: config
  } do
    conn =
      :post
      |> conn("https://mcp.example.com/mcp/user")
      |> authenticate(config,
        resource_path: "/mcp/user",
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
    opts = [config: &Factory.config/0, resource_path: "/mcp", base_url: "https://mcp.example.com"]

    assert opts |> Authenticate.init() |> Macro.escape()
  end

  defp authenticate(conn, config, opts \\ []) do
    opts =
      Keyword.merge(
        [
          config: config,
          htu: fn _conn -> Factory.htu() end
        ],
        opts
      )

    Authenticate.call(conn, Authenticate.init(opts))
  end

  defp form_post(params) do
    :post
    |> conn("/mcp", params)
    |> put_req_header("content-type", "application/x-www-form-urlencoded")
  end
end
