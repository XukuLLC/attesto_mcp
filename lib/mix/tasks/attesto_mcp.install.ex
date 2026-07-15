# Module name is `Mix.Tasks.AttestoMcp.Install` (not `AttestoMCP`) because Mix
# resolves `mix attesto_mcp.install` via `Mix.Utils.command_to_module_name/1`,
# which camelizes each underscore-delimited segment and yields `AttestoMcp`. The
# task will not be found under any other casing. Every reference to the library
# itself keeps the `AttestoMCP` acronym casing.
defmodule Mix.Tasks.AttestoMcp.Install.Docs do
  @moduledoc false

  @spec short_doc() :: String.t()
  def short_doc, do: "Scaffolds an MCP protected resource into a Phoenix application"

  @spec example() :: String.t()
  def example, do: "mix attesto_mcp.install --resource-path /mcp --scopes mcp:use"

  @spec long_doc() :: String.t()
  def long_doc do
    """
    #{short_doc()}

    Wires the building blocks an MCP server needs to act as an OAuth 2.0
    protected resource into a host Phoenix application:

      * The OAuth 2.0 Protected Resource Metadata endpoint (RFC 9728 Section 3),
        mounted from the per-resource well-known path (RFC 9728 Section 3.1) with
        the same route form emitted by
        `AttestoMCP.Router.attesto_mcp_protected_resource_metadata/2`. The
        installer emits `root: false`, so multiple installations never create
        an ambiguous or order-dependent root document; a host may explicitly
        nominate one resource later if legacy-client compatibility requires it.
      * A Phoenix pipeline that enforces bearer-token authentication and the
        required OAuth scopes (RFC 6750 Bearer Token Usage, RFC 6749 Section 3.3
        scope semantics) via `AttestoMCP.Plug.ProtectResource`. The generated
        protection derives the exact resource audience from the same path as
        metadata and rejects tokens issued to sibling MCP resources.

    This task is idempotent per resource path: re-running it recognizes only a
    complete matching scaffold, so it will not duplicate the pipeline, metadata,
    or protected scope. Legacy raw metadata routes, implicit root ownership, and
    partial target wiring produce an actionable issue without changing the router;
    make root ownership explicit and complete or remove the old scaffold before
    rerunning the installer.

    ## Example

    ```sh
    #{example()}
    ```

    ## Options

    * `--resource-path` - the path component of the protected resource being
      served, for example `/mcp` (RFC 9728 Section 3.1). The metadata endpoint is
      mounted at `/.well-known/oauth-protected-resource<resource-path>` and the
      protecting pipeline is piped through the matching scope. Defaults to `/mcp`.
    * `--scopes` - a comma-separated list of OAuth scope strings the bearer token
      must carry to access the protected resource (RFC 6749 Section 3.3). Defaults
      to `mcp:use`.
    * `--router` - the Phoenix router module to wire the routes into. Defaults to
      the application's discovered router.
    """
  end
end

if Code.ensure_loaded?(Igniter) do
  defmodule Mix.Tasks.AttestoMcp.Install do
    # `@shortdoc` is a compile-time module attribute evaluated before any `alias`
    # below takes effect, so it cannot reference the sibling `...Install.Docs`
    # module by an alias; the literal is inlined here (kept in sync with
    # `Docs.short_doc/0`) rather than fully qualifying the nested module.
    @shortdoc "Scaffolds an MCP protected resource into a Phoenix application"

    @moduledoc Mix.Tasks.AttestoMcp.Install.Docs.long_doc()

    use Igniter.Mix.Task

    alias AttestoMCP.Plug.ProtectResource
    alias Igniter.Code.Common
    alias Igniter.Code.Function
    alias Igniter.Code.Keyword, as: CodeKeyword
    alias Igniter.Code.Module, as: CodeModule
    alias Igniter.Libs.Phoenix
    alias Igniter.Mix.Task.Info
    alias Igniter.Project.Module, as: ProjectModule
    alias Mix.Tasks.AttestoMcp.Install.Docs

    @default_resource_path "/mcp"
    @default_scopes "mcp:use"

    @impl Igniter.Mix.Task
    def info(_argv, _composing_task) do
      %Info{
        group: :attesto_mcp,
        example: Docs.example(),
        schema: [resource_path: :string, scopes: :string, router: :string],
        aliases: []
      }
    end

    @impl Igniter.Mix.Task
    def igniter(igniter) do
      options = igniter.args.options
      resource_path = normalize_resource_path(options[:resource_path] || @default_resource_path)
      scopes = parse_scopes(options[:scopes] || @default_scopes)
      router = resolve_router(igniter, options)
      pipeline_name = pipeline_name(resource_path)

      case installation_state(igniter, router, pipeline_name, resource_path, scopes) do
        {igniter, :installed} ->
          Igniter.add_notice(
            igniter,
            "AttestoMCP protected resource #{resource_path} is already installed; no router changes were made."
          )

        {igniter, :absent} ->
          igniter
          |> ensure_router_use(router)
          |> add_protect_pipeline(router, pipeline_name, resource_path, scopes)
          |> add_metadata_scope(router, resource_path, scopes)
          |> add_protected_scope(router, pipeline_name, resource_path)
          |> Igniter.add_notice("""
          AttestoMCP protected resource scaffolded for #{resource_path}.

          The host router now mounts the RFC 9728 path-inserted protected
          resource metadata endpoint (with no implicit root document) and a
          #{inspect(pipeline_name)} pipeline that enforces the #{inspect(scopes)}
          scope(s) and this resource's exact audience via
          AttestoMCP.Plug.ProtectResource.

          No origin is pinned: both metadata and protection derive the resource
          origin from each request. Behind a reverse proxy, add the same
          `:base_url` (or `:origin`) option to the generated metadata declaration
          and ProtectResource plug.

          Next steps:

            * Mount your MCP transport plug inside the #{inspect(resource_path)} scope.
            * Configure the metadata document's authorization servers per the
              AttestoMCP README.
          """)

        {igniter, {:conflict, issue}} ->
          Igniter.add_issue(igniter, issue)
      end
    end

    # Mount metadata through the public router macro so generated applications
    # inherit its RFC 9728 behavior. `root: false` is the safe repeatable default:
    # every resource gets its path-inserted document, and no install silently
    # claims a shared root whose meaning would depend on insertion order.
    defp add_metadata_scope(igniter, router, resource_path, scopes) do
      Phoenix.add_scope(
        igniter,
        "/",
        """
        attesto_mcp_protected_resource_metadata #{inspect(resource_path)},
          scopes: #{inspect(scopes)},
          root: false
        """,
        router: router
      )
    end

    # The protected resource itself is piped through the bearer-token pipeline
    # (RFC 6750). The MCP transport plug is mounted here by the application.
    defp add_protected_scope(igniter, router, pipeline_name, resource_path) do
      Phoenix.add_scope(
        igniter,
        resource_path,
        """
        pipe_through #{inspect(pipeline_name)}
        # Mount your MCP transport plug here.
        """,
        router: router
      )
    end

    defp add_protect_pipeline(igniter, router, pipeline_name, resource_path, scopes) do
      Phoenix.add_pipeline(
        igniter,
        pipeline_name,
        """
        plug :accepts, ["json"]
        plug AttestoMCP.Plug.ProtectResource,
          scopes: #{inspect(scopes)},
          resource: #{inspect(resource_path)},
          resource_audience: :resource
        """,
        router: router
      )
    end

    # Classify the existing router before any edit. This makes a complete new
    # scaffold byte-for-byte idempotent, while legacy raw routes, an implicit
    # single-resource root, or partial/manual wiring stop with migration advice
    # instead of being combined into duplicate or under-protected routes.
    defp installation_state(igniter, router, pipeline_name, resource_path, scopes) do
      {igniter, _source, zipper} = ProjectModule.find_module!(igniter, router)

      state = classify_installation(zipper, pipeline_name, resource_path, scopes)
      {igniter, state}
    end

    defp classify_installation(zipper, pipeline_name, resource_path, scopes) do
      cond do
        legacy_metadata_route?(zipper) ->
          {:conflict, legacy_route_issue(resource_path)}

        implicit_root_declaration?(zipper) ->
          {:conflict, implicit_root_issue(resource_path)}

        metadata_declaration?(zipper, resource_path) ->
          declared_installation_state(zipper, pipeline_name, resource_path, scopes)

        target_artifact?(zipper, pipeline_name, resource_path) ->
          {:conflict, partial_installation_issue(resource_path, scopes)}

        true ->
          :absent
      end
    end

    defp declared_installation_state(zipper, pipeline_name, resource_path, scopes) do
      if complete_installation?(zipper, pipeline_name, resource_path, scopes) do
        :installed
      else
        {:conflict, partial_installation_issue(resource_path, scopes)}
      end
    end

    defp complete_installation?(zipper, pipeline_name, resource_path, scopes) do
      router_uses_macro?(zipper) and
        complete_metadata_declaration?(zipper, resource_path, scopes) and
        complete_protection_pipeline?(zipper, pipeline_name, resource_path, scopes) and
        protected_scope?(zipper, pipeline_name, resource_path)
    end

    defp router_uses_macro?(zipper) do
      CodeModule.move_to_module_using(zipper, AttestoMCP.Router) != :error
    end

    defp metadata_declaration?(zipper, resource_path) do
      match?(
        {:ok, _},
        Function.move_to_function_call(
          zipper,
          :attesto_mcp_protected_resource_metadata,
          [1, 2],
          &Function.argument_equals?(&1, 0, resource_path)
        )
      )
    end

    defp complete_metadata_declaration?(zipper, resource_path, scopes) do
      match?(
        {:ok, _},
        Function.move_to_function_call(
          zipper,
          :attesto_mcp_protected_resource_metadata,
          2,
          fn declaration ->
            Function.argument_equals?(declaration, 0, resource_path) and
              Function.argument_matches_predicate?(
                declaration,
                1,
                &metadata_opts_match?(&1, scopes)
              )
          end
        )
      )
    end

    defp metadata_opts_match?(opts, scopes) do
      keyword_value_equals?(opts, :scopes, scopes) and explicit_root?(opts)
    end

    defp explicit_root?(opts) do
      keyword_value_equals?(opts, :root, false) or keyword_value_equals?(opts, :root, true)
    end

    defp complete_protection_pipeline?(zipper, pipeline_name, resource_path, scopes) do
      match?(
        {:ok, _},
        Function.move_to_function_call(zipper, :pipeline, 2, fn pipeline ->
          Function.argument_equals?(pipeline, 0, pipeline_name) and
            pipeline_protects_resource?(pipeline, resource_path, scopes)
        end)
      )
    end

    defp pipeline_declared?(zipper, pipeline_name) do
      match?(
        {:ok, _},
        Function.move_to_function_call(
          zipper,
          :pipeline,
          2,
          &Function.argument_equals?(&1, 0, pipeline_name)
        )
      )
    end

    defp pipeline_protects_resource?(pipeline, resource_path, scopes) do
      match?(
        {:ok, _},
        Common.within(pipeline, fn subtree ->
          Function.move_to_function_call(subtree, :plug, 2, fn plug ->
            Function.argument_equals?(plug, 0, ProtectResource) and
              Function.argument_matches_predicate?(
                plug,
                1,
                &protection_opts_match?(&1, resource_path, scopes)
              )
          end)
        end)
      )
    end

    defp protection_opts_match?(opts, resource_path, scopes) do
      keyword_value_equals?(opts, :scopes, scopes) and
        keyword_value_equals?(opts, :resource, resource_path) and
        keyword_value_equals?(opts, :resource_audience, :resource)
    end

    defp protected_scope?(zipper, pipeline_name, resource_path) do
      match?(
        {:ok, _},
        Function.move_to_function_call(zipper, :scope, [2, 3], fn scope ->
          Function.argument_equals?(scope, 0, resource_path) and
            scope_uses_pipeline?(scope, pipeline_name)
        end)
      )
    end

    defp scope_uses_pipeline?(scope, pipeline_name) do
      match?(
        {:ok, _},
        Common.within(scope, fn subtree ->
          Function.move_to_function_call(
            subtree,
            :pipe_through,
            1,
            &Function.argument_equals?(&1, 0, pipeline_name)
          )
        end)
      )
    end

    defp target_artifact?(zipper, pipeline_name, resource_path) do
      pipeline_declared?(zipper, pipeline_name) or
        pipeline_referenced?(zipper, pipeline_name) or
        protection_for_resource?(zipper, resource_path)
    end

    defp pipeline_referenced?(zipper, pipeline_name) do
      match?(
        {:ok, _},
        Function.move_to_function_call(
          zipper,
          :pipe_through,
          1,
          &Function.argument_equals?(&1, 0, pipeline_name)
        )
      )
    end

    defp protection_for_resource?(zipper, resource_path) do
      match?(
        {:ok, _},
        Function.move_to_function_call(zipper, :plug, 2, fn plug ->
          Function.argument_equals?(plug, 0, ProtectResource) and
            Function.argument_matches_predicate?(plug, 1, fn opts ->
              keyword_value_equals?(opts, :resource, resource_path)
            end)
        end)
      )
    end

    defp keyword_value_equals?(opts, key, expected) do
      case CodeKeyword.get_key(opts, key) do
        {:ok, value} -> Common.nodes_equal?(value, expected)
        :error -> false
      end
    end

    defp legacy_metadata_route?(zipper) do
      match?(
        {:ok, _},
        Function.move_to_function_call(zipper, :get, [3, 4], fn route ->
          Function.argument_equals?(route, 1, AttestoMCP.MetadataController)
        end)
      )
    end

    defp implicit_root_declaration?(zipper) do
      match?(
        {:ok, _},
        Function.move_to_function_call(
          zipper,
          :attesto_mcp_protected_resource_metadata,
          [1, 2],
          &implicit_root?/1
        )
      )
    end

    defp implicit_root?(declaration) do
      Function.function_call?(declaration, :attesto_mcp_protected_resource_metadata, 1) or
        Function.argument_matches_predicate?(declaration, 1, fn opts ->
          not explicit_root?(opts)
        end)
    end

    defp legacy_route_issue(resource_path) do
      """
      attesto_mcp.install found legacy raw AttestoMCP.MetadataController routes before installing
      #{inspect(resource_path)}, so no router changes were made. Replace the legacy raw `get`
      routes with `use AttestoMCP.Router` and one
      `attesto_mcp_protected_resource_metadata/2` declaration per resource. Set `root: false`
      on every resource (or explicitly set `root: true` on exactly one), and add matching
      `resource: <path>` plus `resource_audience: :resource` options to each ProtectResource
      pipeline. Then rerun the installer.
      """
    end

    defp implicit_root_issue(resource_path) do
      """
      attesto_mcp.install found an existing protected-resource metadata declaration with an
      implicit single-resource root before installing #{inspect(resource_path)}, so no router
      changes were made. First make root ownership explicit on the existing declaration:
      use `root: false` for no shared root, or `root: true` for the one resource that should own
      it. Then rerun the installer.
      """
    end

    defp partial_installation_issue(resource_path, scopes) do
      """
      attesto_mcp.install found an existing declaration for #{inspect(resource_path)}, but it
      does not match a complete audience-confined scaffold for scopes #{inspect(scopes)}, so no
      router changes were made. Ensure the declaration uses those scopes and an explicit boolean
      `root` option, its ProtectResource pipeline uses the same scopes plus
      `resource: #{inspect(resource_path)}` and `resource_audience: :resource`, and the resource
      scope pipes through that pipeline. Alternatively remove the partial wiring and rerun the
      installer.
      """
    end

    # The public metadata macro is imported exactly once, immediately after the
    # router's own `use` declaration when possible, so every generated scope can
    # expand it regardless of where Igniter inserts that scope.
    defp ensure_router_use(igniter, router) do
      ProjectModule.find_and_update_module!(igniter, router, fn zipper ->
        case CodeModule.move_to_use(zipper, AttestoMCP.Router) do
          {:ok, _present} ->
            {:ok, zipper}

          :error ->
            {:ok, add_router_use(igniter, zipper)}
        end
      end)
    end

    defp add_router_use(igniter, zipper) do
      case Phoenix.move_to_router_use(igniter, zipper) do
        {:ok, router_use} ->
          Common.add_code(router_use, "use AttestoMCP.Router")

        :error ->
          Common.add_code(zipper, "use AttestoMCP.Router", placement: :before)
      end
    end

    defp resolve_router(igniter, options) do
      case options[:router] do
        nil ->
          case Phoenix.select_router(igniter) do
            {_igniter, nil} -> Mix.raise("No Phoenix router found")
            {_igniter, router} -> router
          end

        router ->
          Igniter.Project.Module.parse(router)
      end
    end

    # RFC 9728 Section 3.1 keys metadata off the resource path component; the
    # leading slash is required for the well-known suffix and the protected scope.
    defp normalize_resource_path("/" <> _ = path), do: path
    defp normalize_resource_path(path), do: "/" <> path

    defp parse_scopes(scopes) do
      scopes
      |> String.split(",", trim: true)
      |> Enum.map(&String.trim/1)
      |> Enum.reject(&(&1 == ""))
    end

    # Derive a stable, bounded pipeline atom. The readable slug is not unique
    # (`/mcp/foo-bar` and `/mcp/foo/bar` both normalize alike), so include a
    # SHA-256 suffix to keep distinct resources on collision-resistant names.
    defp pipeline_name(resource_path) do
      slug =
        resource_path
        |> String.replace(~r/[^a-zA-Z0-9]+/, "_")
        |> String.trim("_")
        |> String.slice(0, 40)

      slug = if slug == "", do: "resource", else: slug

      digest =
        :sha256
        |> :crypto.hash(resource_path)
        |> Base.encode16(case: :lower)

      :"mcp_protected_#{slug}_#{digest}"
    end
  end
else
  defmodule Mix.Tasks.AttestoMcp.Install do
    @shortdoc "#{Mix.Tasks.AttestoMcp.Install.Docs.short_doc()} | Install `igniter` to use"

    @moduledoc Mix.Tasks.AttestoMcp.Install.Docs.long_doc()

    use Mix.Task

    @impl Mix.Task
    def run(_argv) do
      Mix.shell().error("""
      The task 'attesto_mcp.install' requires igniter. Install `igniter` and run it with:

          mix igniter.install attesto_mcp

      or add `{:igniter, "~> 0.5"}` to your deps and run `mix attesto_mcp.install` again.
      """)

      exit({:shutdown, 1})
    end
  end
end
