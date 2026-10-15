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

      # More than one resource, so the root document must be claimed explicitly.
      attesto_mcp_protected_resource_metadata "/mcp/foo",
        scopes: [Scopes.server("foo", :tools_call)],
        root: true

      attesto_mcp_protected_resource_metadata "/mcp/bar", scopes: [Scopes.server("bar", :tools_call)]

      attesto_mcp_protected_resource_metadata "/mcp/pinned",
        scopes: [Scopes.server("pinned", :tools_call)],
        base_url: "https://canonical.example"

      attesto_mcp_protected_resource_metadata "/mcp/tuple",
        scopes: [Scopes.server("tuple", :tools_call)],
        base_url: {Origins, :canonical}

      attesto_mcp_protected_resource_metadata "mcp/no-leading",
        scopes: [Scopes.server("normalized", :tools_call)]
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

  test "the root compatibility route resolves to the resource that claimed root: true" do
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

  test "normalizes a resource path without a leading slash for route and metadata" do
    metadata = get_metadata("/.well-known/oauth-protected-resource/mcp/no-leading")

    assert metadata["resource"] == "https://mcp.example.com/mcp/no-leading"
    assert metadata["scopes_supported"] == [Scopes.server("normalized", :tools_call)]
  end

  test "refuses declaration inside a path-prefixed Phoenix scope" do
    module = "AttestoMCP.NestedRouter#{System.unique_integer([:positive])}"

    source = """
    defmodule #{module} do
      use Phoenix.Router
      use AttestoMCP.Router

      scope "/api" do
        attesto_mcp_protected_resource_metadata "/mcp", scopes: ["mcp:use"], root: false
      end
    end
    """

    assert_raise ArgumentError, ~r/must be declared at the router root/, fn ->
      Code.compile_string(source)
    end
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
