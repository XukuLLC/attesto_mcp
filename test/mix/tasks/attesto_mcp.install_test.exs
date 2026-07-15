defmodule Mix.Tasks.AttestoMcp.InstallTest do
  # Module name is `AttestoMcp` (not `AttestoMCP`) so the test module mirrors the
  # task module Mix resolves; see the note on Mix.Tasks.AttestoMcp.Install.
  use ExUnit.Case, async: true

  import Igniter.Test

  # The router is passed explicitly so the task never falls back to Igniter's
  # module-scanning router discovery, which is not deterministic when the whole
  # suite runs against the shared Igniter test scratch project.
  @argv ["--resource-path", "/mcp", "--scopes", "mcp:use", "--router", "TestWeb.Router"]
  @alpha_argv [
    "--resource-path",
    "/mcp/alpha",
    "--scopes",
    "alpha:tools",
    "--router",
    "TestWeb.Router"
  ]
  @beta_argv [
    "--resource-path",
    "/mcp/beta",
    "--scopes",
    "beta:tools",
    "--router",
    "TestWeb.Router"
  ]

  describe "mix attesto_mcp.install" do
    test "scaffolds the public metadata macro and audience-confined protection" do
      source =
        phx_test_project()
        |> Igniter.compose_task("attesto_mcp.install", @argv)
        |> apply_igniter!()
        |> router_source()

      assert source =~ "use AttestoMCP.Router"
      assert source =~ "attesto_mcp_protected_resource_metadata(\"/mcp\""
      assert source =~ ~s(scopes: ["mcp:use"])
      assert source =~ "root: false"

      assert source =~ "AttestoMCP.Plug.ProtectResource"
      assert source =~ ~s(resource: "/mcp")
      assert source =~ "resource_audience: :resource"

      # The installer delegates route generation to the public macro and never
      # hand-writes either a controller route or an implicit root document.
      refute source =~ "AttestoMCP.MetadataController"
      refute source =~ ~s(get("/oauth-protected-resource")
    end

    test "a true re-run of the same resource is a byte-for-byte no-op" do
      installed =
        phx_test_project()
        |> Igniter.compose_task("attesto_mcp.install", @argv)
        |> apply_igniter!()

      installed_router = router_source(installed)

      rerun_router =
        installed
        |> Igniter.compose_task("attesto_mcp.install", @argv)
        |> apply_igniter!()
        |> router_source()

      assert rerun_router == installed_router
      assert occurrences(rerun_router, "attesto_mcp_protected_resource_metadata") == 1
      assert occurrences(rerun_router, "AttestoMCP.Plug.ProtectResource") == 1
    end

    test "a re-run accepts an explicitly nominated root owner" do
      installed =
        phx_test_project()
        |> Igniter.compose_task("attesto_mcp.install", @argv)
        |> apply_igniter!()

      explicit_root_router =
        installed
        |> router_source()
        |> String.replace("root: false", "root: true")

      explicit_root = replace_router_source(installed, explicit_root_router)

      rerun_router =
        explicit_root
        |> Igniter.compose_task("attesto_mcp.install", @argv)
        |> apply_igniter!()
        |> router_source()

      assert rerun_router == explicit_root_router
    end

    test "two resources get distinct metadata, scopes, and protection with no root owner" do
      source =
        phx_test_project()
        |> Igniter.compose_task("attesto_mcp.install", @alpha_argv)
        |> apply_igniter!()
        |> Igniter.compose_task("attesto_mcp.install", @beta_argv)
        |> apply_igniter!()
        |> router_source()

      assert occurrences(source, "use AttestoMCP.Router") == 1
      assert occurrences(source, "attesto_mcp_protected_resource_metadata") == 2
      assert occurrences(source, "root: false") == 2
      assert occurrences(source, "AttestoMCP.Plug.ProtectResource") == 2
      assert occurrences(source, "resource_audience: :resource") == 2

      assert source =~
               ~r/attesto_mcp_protected_resource_metadata\("\/mcp\/alpha".*?scopes: \["alpha:tools"\].*?root: false/s

      assert source =~
               ~r/attesto_mcp_protected_resource_metadata\("\/mcp\/beta".*?scopes: \["beta:tools"\].*?root: false/s

      assert source =~
               ~r/Plug\.ProtectResource.*?scopes: \["alpha:tools"\].*?resource: "\/mcp\/alpha".*?resource_audience: :resource/s

      assert source =~
               ~r/Plug\.ProtectResource.*?scopes: \["beta:tools"\].*?resource: "\/mcp\/beta".*?resource_audience: :resource/s

      refute source =~ "AttestoMCP.MetadataController"
      refute source =~ ~s(get("/oauth-protected-resource")
    end

    test "resource paths with the same readable slug still get distinct pipelines" do
      foo_dash = [
        "--resource-path",
        "/mcp/foo-bar",
        "--scopes",
        "foo:tools",
        "--router",
        "TestWeb.Router"
      ]

      foo_slash = [
        "--resource-path",
        "/mcp/foo/bar",
        "--scopes",
        "bar:tools",
        "--router",
        "TestWeb.Router"
      ]

      source =
        phx_test_project()
        |> Igniter.compose_task("attesto_mcp.install", foo_dash)
        |> apply_igniter!()
        |> Igniter.compose_task("attesto_mcp.install", foo_slash)
        |> apply_igniter!()
        |> router_source()

      pipeline_names =
        ~r/pipeline :(mcp_protected_[a-zA-Z0-9_]+) do/
        |> Regex.scan(source, capture: :all_but_first)
        |> List.flatten()

      assert length(pipeline_names) == 2
      assert length(Enum.uniq(pipeline_names)) == 2
    end

    test "the notice explains request-derived origins and reverse-proxy pinning" do
      igniter =
        phx_test_project()
        |> Igniter.compose_task("attesto_mcp.install", @argv)

      assert_has_notice(igniter, fn notice ->
        notice =~ "both metadata and protection derive the resource" and
          notice =~ ":base_url" and notice =~ ":origin" and
          notice =~ "reverse proxy"
      end)
    end

    test "rejects degenerate resource paths before changing the router" do
      for path <- ["", "/", "/mcp/../admin", "/mcp?tenant=one"] do
        argv = ["--resource-path", path, "--scopes", "mcp:use", "--router", "TestWeb.Router"]

        assert_raise Mix.Error, ~r/--resource-path/, fn ->
          phx_test_project()
          |> Igniter.compose_task("attesto_mcp.install", argv)
        end
      end
    end

    test "rejects an empty scope list before changing the router" do
      for scopes <- ["", ",", " , "] do
        argv = ["--resource-path", "/mcp", "--scopes", scopes, "--router", "TestWeb.Router"]

        assert_raise Mix.Error, ~r/at least one OAuth scope/, fn ->
          phx_test_project()
          |> Igniter.compose_task("attesto_mcp.install", argv)
        end
      end
    end

    test "legacy raw metadata routes stop without changing the router" do
      seeded =
        phx_test_project()
        |> replace_router_source("""
        defmodule TestWeb.Router do
          use TestWeb, :router

          scope "/.well-known" do
            get "/oauth-protected-resource", AttestoMCP.MetadataController, :show
          end
        end
        """)

      before = router_source(seeded)
      conflicted = Igniter.compose_task(seeded, "attesto_mcp.install", @beta_argv)

      assert_has_issue(conflicted, &(&1 =~ "legacy raw AttestoMCP.MetadataController routes"))
      assert router_source(conflicted) == before
    end

    test "an implicit root owner stops a multi-resource install without changes" do
      seeded =
        phx_test_project()
        |> replace_router_source("""
        defmodule TestWeb.Router do
          use TestWeb, :router
          use AttestoMCP.Router

          scope "/" do
            attesto_mcp_protected_resource_metadata "/mcp/alpha",
              scopes: ["alpha:tools"]
          end
        end
        """)

      before = router_source(seeded)
      conflicted = Igniter.compose_task(seeded, "attesto_mcp.install", @beta_argv)

      assert_has_issue(conflicted, &(&1 =~ "implicit single-resource root"))
      assert router_source(conflicted) == before
    end

    test "an explicit :auto root sentinel is still treated as implicit ownership" do
      seeded =
        phx_test_project()
        |> replace_router_source("""
        defmodule TestWeb.Router do
          use TestWeb, :router
          use AttestoMCP.Router

          scope "/" do
            attesto_mcp_protected_resource_metadata "/mcp/alpha",
              scopes: ["alpha:tools"],
              root: :auto
          end
        end
        """)

      before = router_source(seeded)
      conflicted = Igniter.compose_task(seeded, "attesto_mcp.install", @beta_argv)

      assert_has_issue(conflicted, &(&1 =~ "implicit single-resource root"))
      assert router_source(conflicted) == before
    end

    test "a non-literal metadata path stops instead of adding a duplicate route" do
      seeded =
        phx_test_project()
        |> replace_router_source("""
        defmodule TestWeb.Router do
          use TestWeb, :router
          use AttestoMCP.Router

          @resource_path "/mcp"

          scope "/" do
            attesto_mcp_protected_resource_metadata @resource_path,
              scopes: ["mcp:use"],
              root: false
          end
        end
        """)

      before = router_source(seeded)
      conflicted = Igniter.compose_task(seeded, "attesto_mcp.install", @argv)

      assert_has_issue(conflicted, &(&1 =~ "resource path is not a literal string"))
      assert router_source(conflicted) == before
    end

    test "a partial target declaration stops without adding protection" do
      seeded =
        phx_test_project()
        |> replace_router_source("""
        defmodule TestWeb.Router do
          use TestWeb, :router
          use AttestoMCP.Router

          scope "/" do
            attesto_mcp_protected_resource_metadata "/mcp",
              scopes: ["mcp:use"],
              root: false
          end
        end
        """)

      before = router_source(seeded)
      conflicted = Igniter.compose_task(seeded, "attesto_mcp.install", @argv)

      assert_has_issue(conflicted, &(&1 =~ "complete audience-confined scaffold"))
      assert router_source(conflicted) == before
    end

    test "target pipeline artifacts without metadata stop instead of duplicating scopes" do
      installed =
        phx_test_project()
        |> Igniter.compose_task("attesto_mcp.install", @argv)
        |> apply_igniter!()

      without_metadata =
        installed
        |> router_source()
        |> String.replace(
          ~r/\n\s*scope "\/" do\n\s*attesto_mcp_protected_resource_metadata\("\/mcp",.*?\n\s*end\n/s,
          "\n"
        )

      seeded = replace_router_source(installed, without_metadata)
      before = router_source(seeded)
      conflicted = Igniter.compose_task(seeded, "attesto_mcp.install", @argv)

      assert_has_issue(conflicted, &(&1 =~ "complete audience-confined scaffold"))
      assert router_source(conflicted) == before
    end
  end

  # Read the post-apply contents of the generated router from the Igniter's
  # Rewrite project. `Igniter.Test` exposes no public source-reader, so go
  # through Rewrite directly (the same path its own assertions use).
  defp router_source(igniter) do
    igniter.rewrite
    |> Rewrite.source!("lib/test_web/router.ex")
    |> Rewrite.Source.get(:content)
  end

  defp replace_router_source(igniter, content) do
    Igniter.update_file(igniter, "lib/test_web/router.ex", fn source ->
      Rewrite.Source.update(source, :content, content)
    end)
  end

  defp occurrences(source, needle), do: source |> :binary.matches(needle) |> length()
end
