defmodule AttestoMCP.Plug.RequireScopesTest do
  @moduledoc false
  use ExUnit.Case, async: false

  import Plug.Conn
  import Plug.Test

  alias AttestoMCP.Plug.Authenticate
  alias AttestoMCP.Plug.RequireScopes
  alias AttestoMCP.Scopes
  alias AttestoMCP.Test.Factory

  setup do
    %{config: Factory.config()}
  end

  test "required scope is accepted", %{config: config} do
    token = Factory.access_token(config, scopes: [Scopes.tools_call()])

    conn =
      :post
      |> conn("/mcp")
      |> put_req_header("authorization", "Bearer " <> token)
      |> authenticate(config)
      |> require_scopes([Scopes.tools_call()])

    refute conn.halted
  end

  test "required scope is rejected", %{config: config} do
    token = Factory.access_token(config, scopes: [Scopes.resources_read()])

    conn =
      :post
      |> conn("/mcp")
      |> put_req_header("authorization", "Bearer " <> token)
      |> authenticate(config)
      |> require_scopes([Scopes.tools_call()])

    assert conn.halted
    assert conn.status == 403
    assert JSON.decode!(conn.resp_body)["error"] == "insufficient_scope"
  end

  test "threads the :no_store hook onto a scope rejection (core parity)", %{config: config} do
    token = Factory.access_token(config, scopes: [Scopes.resources_read()])

    conn =
      :post
      |> conn("/mcp")
      |> put_req_header("authorization", "Bearer " <> token)
      |> authenticate(config)
      |> RequireScopes.call(
        RequireScopes.init(
          scopes: [Scopes.tools_call()],
          no_store: fn c -> Plug.Conn.put_resp_header(c, "x-no-store", "host") end
        )
      )

    assert conn.status == 403
    assert ["host"] == Plug.Conn.get_resp_header(conn, "x-no-store")
    # The host hook replaced core's default no-store path (pragma absent).
    assert [] == Plug.Conn.get_resp_header(conn, "pragma")
  end

  test "rejects simultaneous scalar and list scope options" do
    assert_raise ArgumentError, ~r/either :scope or :scopes/, fn ->
      RequireScopes.init(scope: Scopes.tools_call(), scopes: [Scopes.tools_call()])
    end
  end

  test "rejects duplicate and malformed static scope sets" do
    assert_raise ArgumentError, ~r/unique RFC 6749/, fn ->
      RequireScopes.init(scopes: [Scopes.tools_call(), Scopes.tools_call()])
    end

    for scopes <- [[], [""], ["contains space"], [123]] do
      assert_raise ArgumentError, ~r/unique RFC 6749/, fn ->
        RequireScopes.init(scopes: scopes)
      end
    end
  end

  test "rejects wildcard requirements during plug initialization" do
    for scope <- ["*", "mcp:*", "mcp.resource.*"] do
      assert_raise ArgumentError, ~r/concrete scopes.*wildcard requirements/, fn ->
        RequireScopes.init(scopes: [scope])
      end
    end
  end

  test "accepts a valid scalar or unique list" do
    assert %{required: [scope]} = RequireScopes.init(scope: Scopes.tools_call())
    assert scope == Scopes.tools_call()

    assert %{required: [read, call]} =
             RequireScopes.init(scopes: [Scopes.resources_read(), Scopes.tools_call()])

    assert read == Scopes.resources_read()
    assert call == Scopes.tools_call()
  end

  defp authenticate(conn, config) do
    Authenticate.call(conn, Authenticate.init(config: config, htu: fn _conn -> Factory.htu() end))
  end

  defp require_scopes(conn, scopes) do
    RequireScopes.call(conn, RequireScopes.init(scopes: scopes))
  end
end
