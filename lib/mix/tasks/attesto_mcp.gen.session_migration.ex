# `Mix.Ecto` lives in `ecto_sql`, which is optional for attesto_mcp (a consumer
# brings its own). Compile-guard the task so a consumer without ecto_sql can
# still compile the dependency; the fallback errors with install guidance.
if Code.ensure_loaded?(Mix.Ecto) do
  defmodule Mix.Tasks.AttestoMcp.Gen.SessionMigration do
    @shortdoc "Generates the Ecto migration backing AttestoMCP.Anubis.SessionStore.Ecto"

    @moduledoc """
    Generates an Ecto migration that creates the `attesto_mcp_anubis_sessions` table
    backing `AttestoMCP.Anubis.SessionStore.Ecto` (a Postgres-backed
    `Anubis.Server.Session.Store` adapter).

    One row per MCP session, keyed by the client's `Mcp-Session-Id`; `state` is the
    serialized Anubis session map (client_info, capabilities, `frame`), persisted
    so a client can reconnect after a deploy with its initialized state restored.

    ## Usage

        mix attesto_mcp.gen.session_migration --repo MyApp.Repo

    ## Options

      * `--repo` - the Ecto repo the migration is generated for. May be given more
        than once. When omitted the host application's configured repos are used.
      * `--migrations-path` - directory the migration file is written to. Defaults
        to the repo's `priv/<repo>/migrations`.

    The generated migration is reversible.

    Existing installations that used the former `attesto_mcp_sessions` name
    should apply the data-preserving rename documented in the README. Do not
    rename an `attesto_mcp_server` table that has `namespace` and `record`
    columns; that is a different schema.
    """

    use Mix.Task

    import Mix.Ecto, only: [parse_repo: 1, ensure_repo: 2]
    import Mix.Generator

    @switches [repo: [:keep], migrations_path: :string]
    @legacy_base_name "create_attesto_mcp_sessions"
    @base_name "create_attesto_mcp_anubis_sessions"

    @impl Mix.Task
    def run(args) do
      repos = parse_repo(args)
      {opts, _, _} = OptionParser.parse(args, switches: @switches)

      case repos do
        [] ->
          Mix.raise("""
          no Ecto repos available.

          Pass one explicitly with --repo, e.g.

              mix attesto_mcp.gen.session_migration --repo MyApp.Repo
          """)

        repos ->
          Enum.each(repos, &generate_for_repo(&1, opts))
      end
    end

    defp generate_for_repo(repo, opts) do
      ensure_repo(repo, [])

      path = migrations_path(repo, opts)
      create_directory(path)

      file = Path.join(path, "#{timestamp()}_#{@base_name}.exs")

      if !Enum.empty?(Path.wildcard(Path.join(path, "*_#{@base_name}.exs"))) do
        Mix.raise("migration #{inspect(@base_name)} already exists in #{path}; remove it before regenerating")
      end

      reject_legacy_anubis_migration!(path)

      assigns = [module: Module.concat([repo, Migrations, Macro.camelize(@base_name)])]
      create_file(file, migration_template(assigns))
      file
    end

    defp reject_legacy_anubis_migration!(path) do
      path
      |> Path.join("*_#{@legacy_base_name}.exs")
      |> Path.wildcard()
      |> Enum.find(&legacy_anubis_migration?/1)
      |> case do
        nil ->
          :ok

        legacy_file ->
          Mix.raise("""
          found a former AttestoMCP Anubis session migration at #{legacy_file}.

          Do not generate a second, empty session table. Follow the
          data-preserving rename in the README section "Upgrading the Anubis
          Ecto session table" before starting upgraded nodes.

          An attesto_mcp_server migration with `namespace` and `record` columns
          is a different schema and does not trigger this guard.
          """)
      end
    end

    # Both the former Anubis adapter and the native Attesto MCP Server used the
    # same migration base name. Identify the former adapter by its generated
    # column set, while explicitly allowing the native server's namespaced
    # `record` schema.
    defp legacy_anubis_migration?(file) do
      source = File.read!(file)

      old_table?(source) and
        has_columns?(source, ~w(session_id state expires_at)a) and
        not has_columns?(source, ~w(namespace record)a)
    end

    defp old_table?(source), do: Regex.match?(~r/\btable\s*\(\s*:attesto_mcp_sessions\b/, source)

    defp has_columns?(source, columns) do
      Enum.all?(columns, fn column ->
        Regex.match?(~r/\badd\s*(?:\(\s*)?:#{column}\b/, source)
      end)
    end

    defp migrations_path(repo, opts) do
      case Keyword.fetch(opts, :migrations_path) do
        {:ok, path} ->
          path

        :error ->
          config = repo.config()
          priv = config[:priv] || "priv/#{repo |> Module.split() |> List.last() |> Macro.underscore()}"
          Path.join([File.cwd!(), priv, "migrations"])
      end
    end

    defp timestamp do
      {{y, m, d}, {hh, mm, ss}} = :calendar.universal_time()
      Enum.map_join([y, m, d, hh, mm, ss], &pad/1)
    end

    defp pad(i) when i < 10, do: "0" <> Integer.to_string(i)
    defp pad(i), do: Integer.to_string(i)

    embed_template(:migration, """
    defmodule <%= inspect @module %> do
      @moduledoc false

      # Generated by `mix attesto_mcp.gen.session_migration`.
      #
      # Backs AttestoMCP.Anubis.SessionStore.Ecto (an Anubis.Server.Session.Store
      # adapter). One row per MCP session, keyed by the client's Mcp-Session-Id;
      # `state` is the serialized Anubis session map. Expired rows are reaped on
      # load and by the store's cleanup_expired/1.

      use Ecto.Migration

      def up do
        create table(:attesto_mcp_anubis_sessions, primary_key: false) do
          add :session_id, :string, primary_key: true, null: false
          add :state, :map, null: false
          add :expires_at, :utc_datetime_usec, null: false

          timestamps(type: :utc_datetime_usec)
        end

        # Supports both the active-session lookup and the expired-row sweep.
        create index(:attesto_mcp_anubis_sessions, [:expires_at])
      end

      def down do
        drop table(:attesto_mcp_anubis_sessions)
      end
    end
    """)
  end
else
  defmodule Mix.Tasks.AttestoMcp.Gen.SessionMigration do
    @shortdoc "Generates the AttestoMCP session migration | Requires ecto_sql"
    @moduledoc false

    use Mix.Task

    @impl Mix.Task
    def run(_argv) do
      Mix.shell().error("""
      The task 'attesto_mcp.gen.session_migration' requires ecto_sql.

      Add `{:ecto_sql, "~> 3.10"}` (and a driver such as `:postgrex`) to your
      deps and run `mix deps.get`, then re-run this task.
      """)

      exit({:shutdown, 1})
    end
  end
end
