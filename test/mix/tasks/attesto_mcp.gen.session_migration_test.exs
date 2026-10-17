defmodule Mix.Tasks.AttestoMcp.Gen.SessionMigrationTest do
  use ExUnit.Case, async: false

  alias AttestoMCP.Anubis.Session
  alias AttestoMCP.TestRepo
  alias Mix.Tasks.AttestoMcp.Gen.SessionMigration

  setup do
    path =
      Path.join(
        System.tmp_dir!(),
        "attesto-mcp-anubis-migration-#{System.unique_integer([:positive])}"
      )

    File.mkdir_p!(path)
    on_exit(fn -> File.rm_rf!(path) end)
    {:ok, path: path}
  end

  test "generates a distinct Anubis session table matching the runtime schema", %{path: path} do
    SessionMigration.run([
      "--repo",
      inspect(TestRepo),
      "--migrations-path",
      path
    ])

    assert [file] =
             Path.wildcard(Path.join(path, "*_create_attesto_mcp_anubis_sessions.exs"))

    source = File.read!(file)

    assert Session.__schema__(:source) == "attesto_mcp_anubis_sessions"
    assert source =~ "create table(:attesto_mcp_anubis_sessions, primary_key: false)"
    assert source =~ "create index(:attesto_mcp_anubis_sessions, [:expires_at])"
    assert source =~ "drop table(:attesto_mcp_anubis_sessions)"
    refute source =~ "table(:attesto_mcp_sessions"
  end

  test "refuses to overwrite an existing migration for the new table", %{path: path} do
    args = ["--repo", inspect(TestRepo), "--migrations-path", path]
    SessionMigration.run(args)

    assert_raise Mix.Error, ~r/create_attesto_mcp_anubis_sessions.*already exists/, fn ->
      SessionMigration.run(args)
    end

    assert [_file] =
             Path.wildcard(Path.join(path, "*_create_attesto_mcp_anubis_sessions.exs"))
  end

  test "refuses a fresh migration when the former Anubis migration exists", %{path: path} do
    legacy = Path.join(path, "20260101000000_create_attesto_mcp_sessions.exs")

    File.write!(legacy, """
    defmodule Test.Repo.Migrations.CreateAttestoMcpSessions do
      use Ecto.Migration

      def change do
        create table(:attesto_mcp_sessions, primary_key: false) do
          add(:session_id, :string, primary_key: true, null: false)
          add :state, :map, null: false
          add(:expires_at, :utc_datetime_usec, null: false)
        end
      end
    end
    """)

    assert_raise Mix.Error, ~r/former AttestoMCP Anubis session migration.*data-preserving rename/s, fn ->
      SessionMigration.run([
        "--repo",
        inspect(TestRepo),
        "--migrations-path",
        path
      ])
    end

    assert [] == Path.wildcard(Path.join(path, "*_create_attesto_mcp_anubis_sessions.exs"))
  end

  test "allows the native MCP Server migration with namespace and record columns", %{path: path} do
    native = Path.join(path, "20260101000000_create_attesto_mcp_sessions.exs")

    File.write!(native, """
    defmodule Test.Repo.Migrations.CreateAttestoMcpSessions do
      use Ecto.Migration

      def change do
        create table(:attesto_mcp_sessions, primary_key: false) do
          add :namespace, :string, primary_key: true, null: false
          add :session_id, :string, primary_key: true, null: false
          add :record, :map, null: false
          add :expires_at_ms, :bigint, null: false
        end
      end
    end
    """)

    SessionMigration.run([
      "--repo",
      inspect(TestRepo),
      "--migrations-path",
      path
    ])

    assert [_file] =
             Path.wildcard(Path.join(path, "*_create_attesto_mcp_anubis_sessions.exs"))
  end
end
