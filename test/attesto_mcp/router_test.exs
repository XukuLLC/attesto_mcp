defmodule AttestoMCP.RouterTest do
  @moduledoc false
  use ExUnit.Case, async: true

  import Plug.Conn
  import Plug.Test

  alias AttestoMCP.Scopes

  defmodule Origins do
    @moduledoc false
    def canonical(_conn), do: "https://tuple.example"
  end

  defmodule TestRouter do
    @moduledoc false
    use Phoenix.Router
    use AttestoMCP.Router

    pipeline :api do
      plug :accepts, ["json"]
    end

    scope "/" do
      pipe_through :api

      attesto_mcp_protected_resource_metadata "/mcp/foo", scopes: [Scopes.server("foo", :tools_call)]
      attesto_mcp_protected_resource_metadata "/mcp/bar", scopes: [Scopes.server("bar", :tools_call)]

      attesto_mcp_protected_resource_metadata "/mcp/pinned",
        scopes: [Scopes.server("pinned", :tools_call)],
        base_url: "https://canonical.example"

      attesto_mcp_protected_resource_metadata "/mcp/tuple",
        scopes: [Scopes.server("tuple", :tools_call)],
        base_url: {Origins, :canonical}
    end
  end

  test "serves per-resource metadata for the first resource" do
    metadata = get_metadata("/.well-known/oauth-protected-resource/mcp/foo")

    assert metadata["resource"] == "https://mcp.example.com/mcp/foo"
    assert metadata["authorization_servers"] == ["https://mcp.example.com"]
    assert metadata["scopes_supported"] == [Scopes.server("foo", :tools_call)]
  end

  test "serves a distinct document for each resource" do
    foo = get_metadata("/.well-known/oauth-protected-resource/mcp/foo")
    bar = get_metadata("/.well-known/oauth-protected-resource/mcp/bar")

    assert foo["resource"] == "https://mcp.example.com/mcp/foo"
    assert bar["resource"] == "https://mcp.example.com/mcp/bar"
    assert foo["scopes_supported"] == [Scopes.server("foo", :tools_call)]
    assert bar["scopes_supported"] == [Scopes.server("bar", :tools_call)]
  end

  test "the root compatibility route resolves to the first declared resource" do
    metadata = get_metadata("/.well-known/oauth-protected-resource")

    assert metadata["resource"] == "https://mcp.example.com/mcp/foo"
  end

  test "served resource URL matches the ProtectResource challenge derivation" do
    # ProtectResource derives its resource_metadata challenge from
    # AttestoMCP.Metadata.protected_resource_url/2 against the same origin, so
    # the discovered well-known URL and the served metadata document agree.
    metadata = get_metadata("/.well-known/oauth-protected-resource/mcp/foo")

    assert metadata["resource"] ==
             AttestoMCP.Metadata.protected_resource(
               build_conn("/.well-known/oauth-protected-resource/mcp/foo"),
               "/mcp/foo"
             )["resource"]
  end

  test "a :base_url on the macro pins the served resource origin over the request host" do
    # The request arrives at mcp.example.com; the pinned origin must win, proving
    # a string base_url survives the compiled route private and reaches the
    # controller.
    metadata = get_metadata("/.well-known/oauth-protected-resource/mcp/pinned")

    assert metadata["resource"] == "https://canonical.example/mcp/pinned"
  end

  test "an {module, fun} base_url tuple survives compiled route private and pins the resource" do
    # A tuple must actually resolve at request time, not silently fall back to
    # the request host the way an unrecognized term would.
    metadata = get_metadata("/.well-known/oauth-protected-resource/mcp/tuple")

    assert metadata["resource"] == "https://tuple.example/mcp/tuple"
  end

  defp get_metadata(path) do
    conn =
      path
      |> build_conn()
      |> TestRouter.call(TestRouter.init([]))

    assert conn.status == 200
    JSON.decode!(conn.resp_body)
  end

  defp build_conn(path) do
    :get
    |> conn("https://mcp.example.com" <> path)
    |> put_req_header("accept", "application/json")
  end
end
