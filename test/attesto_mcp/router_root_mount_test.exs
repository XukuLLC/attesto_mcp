defmodule AttestoMCP.RouterRootMountTest do
  @moduledoc false
  # The RFC 9728 root compatibility document (`/.well-known/oauth-protected-resource`)
  # is auto-mounted only for a single-resource router; once more than one resource
  # is declared the host must choose its resource explicitly via `:root`.
  use ExUnit.Case, async: true

  import Plug.Conn
  import Plug.Test

  alias AttestoMCP.Scopes
  alias Phoenix.Router.NoRouteError

  defmodule SingleRouter do
    @moduledoc false
    use Phoenix.Router
    use AttestoMCP.Router

    scope "/" do
      attesto_mcp_protected_resource_metadata "/mcp", scopes: [Scopes.tools_call()]
    end
  end

  defmodule NoRootRouter do
    @moduledoc false
    use Phoenix.Router
    use AttestoMCP.Router

    scope "/" do
      attesto_mcp_protected_resource_metadata "/mcp/a", scopes: [Scopes.tools_call()], root: false
      attesto_mcp_protected_resource_metadata "/mcp/b", scopes: [Scopes.tools_call()], root: false
    end
  end

  defmodule LaterRootOwnerRouter do
    @moduledoc false
    use Phoenix.Router
    use AttestoMCP.Router

    scope "/" do
      attesto_mcp_protected_resource_metadata "/mcp/first",
        scopes: ["first:mcp:tools:call"],
        root: false

      attesto_mcp_protected_resource_metadata "/mcp/second",
        scopes: ["second:mcp:tools:call"],
        root: true
    end
  end

  describe "single resource" do
    test "auto-mounts the root document for the sole resource" do
      assert status(SingleRouter, "/.well-known/oauth-protected-resource") == 200
      assert status(SingleRouter, "/.well-known/oauth-protected-resource/mcp") == 200
    end
  end

  describe "root: false" do
    test "serves only the path-suffixed routes, no root document" do
      assert status(NoRootRouter, "/.well-known/oauth-protected-resource/mcp/a") == 200
      assert status(NoRootRouter, "/.well-known/oauth-protected-resource/mcp/b") == 200

      # The root is not mounted at all, so the router has no matching route.
      assert_raise NoRouteError, fn ->
        status(NoRootRouter, "/.well-known/oauth-protected-resource")
      end
    end
  end

  describe "explicit root ownership" do
    test "a later declaration owns the root only when it explicitly claims it" do
      metadata = metadata(LaterRootOwnerRouter, "/.well-known/oauth-protected-resource")

      assert metadata["resource"] == "https://mcp.example.com/mcp/second"
      assert metadata["scopes_supported"] == ["second:mcp:tools:call"]
    end
  end

  describe "ambiguous root is a compile error" do
    test "a second resource with no explicit :root raises" do
      assert_raise ArgumentError, ~r/root.*is ambiguous/s, fn ->
        defmodule AmbiguousRouter do
          use Phoenix.Router
          use AttestoMCP.Router

          scope "/" do
            attesto_mcp_protected_resource_metadata "/mcp/a", scopes: ["a:mcp:tools:call"]
            attesto_mcp_protected_resource_metadata "/mcp/b", scopes: ["b:mcp:tools:call"]
          end
        end
      end
    end

    test "two resources both claiming root: true raises" do
      assert_raise ArgumentError, ~r/only one resource may answer/, fn ->
        defmodule DoubleRootRouter do
          use Phoenix.Router
          use AttestoMCP.Router

          scope "/" do
            attesto_mcp_protected_resource_metadata "/mcp/a", scopes: ["a:mcp:tools:call"], root: true
            attesto_mcp_protected_resource_metadata "/mcp/b", scopes: ["b:mcp:tools:call"], root: true
          end
        end
      end
    end
  end

  defp status(router, path) do
    router
    |> response(path)
    |> Map.fetch!(:status)
  end

  defp metadata(router, path) do
    conn = response(router, path)
    assert conn.status == 200
    JSON.decode!(conn.resp_body)
  end

  defp response(router, path) do
    :get
    |> conn("https://mcp.example.com" <> path)
    |> put_req_header("accept", "application/json")
    |> router.call(router.init([]))
  end
end
