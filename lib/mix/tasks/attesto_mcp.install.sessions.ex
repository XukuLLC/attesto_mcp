# Module name is `Mix.Tasks.AttestoMcp.Install.Sessions` (not `AttestoMCP`)
# because Mix resolves `mix attesto_mcp.install.sessions` via
# `Mix.Utils.command_to_module_name/1`, which camelizes each underscore segment
# and yields `AttestoMcp`. Every reference to the library keeps `AttestoMCP`.
defmodule Mix.Tasks.AttestoMcp.Install.Sessions.Docs do
  @moduledoc false

  @spec short_doc() :: String.t()
  def short_doc, do: "Wires the Ecto-backed Anubis MCP session store into a host application"

  @spec example() :: String.t()
  def example, do: "mix attesto_mcp.install.sessions --repo MyApp.Repo --registry"

  @spec long_doc() :: String.t()
  def long_doc do
    """
    #{short_doc()}

    Configures `AttestoMCP.Anubis.SessionStore.Ecto` - a Postgres-backed
    `Anubis.Server.Session.Store` - so MCP sessions survive a deploy/node
    replacement and a client reconnects with its initialized state restored.

    What it changes (deterministic):

      * adds the `config :anubis_mcp, :session_store` block (enabled, the Ecto
        adapter, the repo, and a 30-minute TTL) to `config/config.exs`;
      * with `--registry`, adds the `horde` dependency for the clustered
        `AttestoMCP.Anubis.Registry.Horde`.

    What it leaves to you (printed as a notice, because the locations are
    app-specific and must not be blind-edited):

      * run `mix attesto_mcp.gen.session_migration --repo <Repo>` to create the
        `attesto_mcp_sessions` table;
      * with `--registry`, wire `registry: {AttestoMCP.Anubis.Registry.Horde, []}`
        into your Anubis server child spec, and connect the nodes (e.g.
        `libcluster`).

    Idempotent: re-running does not duplicate the config block or the dependency.

    ## Example

    ```sh
    #{example()}
    ```

    ## Options

    * `--repo` - the `Ecto.Repo` the session store uses. Defaults to the
      application's `<App>.Repo`.
    * `--registry` - also add the `horde` dependency for the clustered registry
      adapter (and print the wiring notice). Off by default.
    """
  end
end

if Code.ensure_loaded?(Igniter) do
  defmodule Mix.Tasks.AttestoMcp.Install.Sessions do
    @shortdoc "Wires the Ecto-backed Anubis MCP session store into a host application"

    @moduledoc Mix.Tasks.AttestoMcp.Install.Sessions.Docs.long_doc()

    use Igniter.Mix.Task

    alias Igniter.Mix.Task.Info
    alias Igniter.Project.Config
    alias Igniter.Project.Deps
    alias Mix.Tasks.AttestoMcp.Install.Sessions.Docs

    # 30 minutes in milliseconds — matches the Anubis Redis adapter default and
    # `AttestoMCP.Anubis.SessionStore.Ecto`'s own default.
    @default_ttl_ms 1_800_000
    @horde_requirement "~> 0.9"

    @impl Igniter.Mix.Task
    def info(_argv, _composing_task) do
      %Info{
        group: :attesto_mcp,
        example: Docs.example(),
        schema: [repo: :string, registry: :boolean],
        defaults: [registry: false]
      }
    end

    @impl Igniter.Mix.Task
    def igniter(igniter) do
      options = igniter.args.options
      repo = resolve_repo(igniter, options)
      registry? = options[:registry] == true

      igniter
      |> Config.configure(
        "config.exs",
        :anubis_mcp,
        [:session_store],
        enabled: true,
        adapter: AttestoMCP.Anubis.SessionStore.Ecto,
        repo: repo,
        ttl: @default_ttl_ms
      )
      |> maybe_add_horde(registry?)
      |> Igniter.add_notice(notice(repo, registry?))
    end

    defp maybe_add_horde(igniter, false), do: igniter

    defp maybe_add_horde(igniter, true) do
      Deps.add_dep(igniter, {:horde, @horde_requirement})
    end

    defp resolve_repo(igniter, options) do
      case options[:repo] do
        repo when is_binary(repo) and repo != "" -> Igniter.Project.Module.parse(repo)
        _ -> Module.concat(Igniter.Project.Module.module_name_prefix(igniter), Repo)
      end
    end

    defp notice(repo, registry?) do
      base = """
      AttestoMCP Ecto session store configured.

      `config :anubis_mcp, :session_store` now points at
      AttestoMCP.Anubis.SessionStore.Ecto (repo: #{inspect(repo)}).

      Next step — create the backing table:

          mix attesto_mcp.gen.session_migration --repo #{inspect(repo)}
      """

      if registry? do
        base <>
          """

          Registry — the `horde` dependency was added. Wire the clustered
          registry into your Anubis server child spec:

              {MyApp.MCP.Server,
               transport: :streamable_http,
               registry: {AttestoMCP.Anubis.Registry.Horde, []},
               # ...
              }

          and connect the nodes (e.g. libcluster) so Horde discovers peers.
          """
      else
        base
      end
    end
  end
else
  defmodule Mix.Tasks.AttestoMcp.Install.Sessions do
    @shortdoc "#{Mix.Tasks.AttestoMcp.Install.Sessions.Docs.short_doc()} | Install `igniter` to use"

    @moduledoc Mix.Tasks.AttestoMcp.Install.Sessions.Docs.long_doc()

    use Mix.Task

    @impl Mix.Task
    def run(_argv) do
      Mix.shell().error("""
      The task 'attesto_mcp.install.sessions' requires igniter.

      Add `{:igniter, ">= 0.6.0 and < 1.0.0", only: [:dev, :test]}` to your
      deps and run `mix deps.get`, then re-run this task.
      """)

      exit({:shutdown, 1})
    end
  end
end
