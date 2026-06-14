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
        `AttestoMCP.Router.attesto_mcp_protected_resource_metadata/2`.
      * A Phoenix pipeline that enforces bearer-token authentication and the
        required OAuth scopes (RFC 6750 Bearer Token Usage, RFC 6749 Section 3.3
        scope semantics) via `AttestoMCP.Plug.ProtectResource`.

    This task is idempotent: re-running it will not duplicate the pipeline or the
    scopes that a previous run already added. Igniter matches the pipeline by name
    and the scope by its exact contents, so a second run is a no-op.

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

    alias Igniter.Libs.Phoenix
    alias Igniter.Mix.Task.Info
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

      igniter
      |> add_protect_pipeline(router, pipeline_name, resource_path, scopes)
      |> add_metadata_scope(router, resource_path, scopes)
      |> add_protected_scope(router, pipeline_name, resource_path)
      |> Igniter.add_notice("""
      AttestoMCP protected resource scaffolded for #{resource_path}.

      The host router now mounts the RFC 9728 protected resource metadata
      endpoint and a #{inspect(pipeline_name)} pipeline that enforces the
      #{inspect(scopes)} scope(s) via AttestoMCP.Plug.ProtectResource.

      Next steps:

        * Mount your MCP transport plug inside the #{inspect(resource_path)} scope.
        * Configure the metadata document (authorization servers, resource
          identifier) per the AttestoMCP README.
      """)
    end

    # The metadata endpoint is mounted from the bare scope (RFC 9728 Section 3.1
    # serves it from the well-known path, unprotected, so clients can discover the
    # authorization server before they hold a token).
    #
    # The routes are emitted as plain `get` calls to `AttestoMCP.MetadataController`
    # rather than through the `attesto_mcp_protected_resource_metadata/2` router
    # macro, because that macro is only available after `use AttestoMCP.Router` at
    # the module level, and `Igniter.Libs.Phoenix.add_scope/4` injects a scope body
    # without touching the module's `use` declarations. The `get` form needs no
    # import, compiles in any Phoenix router, and is exactly the shape RFC 9728
    # Section 3.1 (path-suffixed) and its root-compatibility companion require. The
    # `:scopes` private is read by the controller and served as `scopes_supported`.
    defp add_metadata_scope(igniter, router, resource_path, scopes) do
      private =
        "%{attesto_mcp_metadata_opts: [scopes: #{inspect(scopes)}], attesto_mcp_resource_path: #{inspect(resource_path)}}"

      Phoenix.add_scope(
        igniter,
        "/.well-known",
        """
        get "/oauth-protected-resource#{resource_path}", AttestoMCP.MetadataController, :show, private: #{private}
        get "/oauth-protected-resource", AttestoMCP.MetadataController, :show, private: #{private}
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

    defp add_protect_pipeline(igniter, router, pipeline_name, _resource_path, scopes) do
      Phoenix.add_pipeline(
        igniter,
        pipeline_name,
        """
        plug :accepts, ["json"]
        plug AttestoMCP.Plug.ProtectResource, scopes: #{inspect(scopes)}
        """,
        router: router
      )
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

    # Derive a stable, unique pipeline atom from the resource path so re-runs
    # match the same pipeline (idempotency) and distinct resources do not collide.
    defp pipeline_name(resource_path) do
      suffix =
        resource_path
        |> String.replace(~r/[^a-zA-Z0-9]+/, "_")
        |> String.trim("_")

      :"mcp_protected_#{suffix}"
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
