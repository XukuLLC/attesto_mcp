defmodule AttestoMCP.Anubis.SessionStore.EctoTest.BareStruct do
  @moduledoc false
  defstruct [:x]
end

defmodule AttestoMCP.Anubis.SessionStore.EctoTest.FailingRepo do
  @moduledoc false

  def insert(_changeset, _opts) do
    raise "private-persistence-sentinel"
  end
end

defmodule AttestoMCP.Anubis.SessionStore.EctoTest do
  @moduledoc """
  Behaviour-conformance tests for the Postgres-backed
  `Anubis.Server.Session.Store` adapter. Tagged `:ecto` so the suite runs only
  when a SQL backend is available.
  """
  use ExUnit.Case, async: false

  alias AttestoMCP.Anubis.SessionStore.Ecto, as: Store
  alias AttestoMCP.Anubis.SessionStore.EctoTest.BareStruct
  alias AttestoMCP.Anubis.SessionStore.EctoTest.FailingRepo
  alias AttestoMCP.Test.ValidJasonStruct
  alias AttestoMCP.TestRepo
  alias Ecto.Adapters.SQL.Sandbox

  @moduletag :ecto

  setup do
    # Igniter's synthetic Phoenix project setup can leave a host-style
    # `:anubis_mcp` session-store config in the VM. Pin this test module to its
    # real repo so the adapter exercises SQL rather than a fictional Test.Repo.
    Application.put_env(:anubis_mcp, :session_store, repo: TestRepo, json_library: Jason)

    :ok = Sandbox.checkout(TestRepo)

    on_exit(fn -> Application.delete_env(:anubis_mcp, :session_store) end)
  end

  defp sid, do: "sess-#{System.unique_integer([:positive])}"

  test "save then load round-trips the state (string-keyed)" do
    id = sid()
    assert :ok = Store.save(id, %{"client_info" => %{"name" => "c"}, "n" => 1}, [])
    assert {:ok, %{"client_info" => %{"name" => "c"}, "n" => 1}} = Store.load(id, [])
  end

  test "documented Anubis table rename preserves legacy rows in both directions" do
    with_isolated_migration_repo(fn ->
      id = sid()
      state = %{"client_info" => %{"name" => "legacy-client"}, "initialized" => true}
      now = DateTime.utc_now() |> DateTime.to_naive()
      expires_at = NaiveDateTime.add(now, 3_600, :second)

      # Start from the current schema, apply the documented reverse migration
      # to reproduce a pre-2.0 Anubis installation, then insert a live row under
      # the legacy name.
      create_isolated_current_session_table()
      rename_anubis_table_down()

      TestRepo.query!(
        """
        INSERT INTO attesto_mcp_sessions
          (session_id, state, expires_at, inserted_at, updated_at)
        VALUES ($1, $2, $3, $4, $4)
        """,
        [id, state, expires_at, now]
      )

      rename_anubis_table_up()

      assert {:ok, ^state} = Store.load(id, [])

      rename_anubis_table_down()

      assert %Postgrex.Result{rows: [[^state]]} =
               TestRepo.query!(
                 "SELECT state FROM attesto_mcp_sessions WHERE session_id = $1",
                 [id]
               )
    end)
  end

  test "save sanitizes non-encodable values before the jsonb insert (no crash)" do
    id = sid()
    # A bare struct + a pid would otherwise raise in the driver and kill the session.
    assert :ok = Store.save(id, %{"user" => %BareStruct{x: 1}, "pid" => self(), "keep" => "v"}, [])
    assert {:ok, state} = Store.load(id, [])
    assert state == %{"keep" => "v"}
  end

  test "save removes NUL-bearing strings and driver-incompatible structs" do
    id = sid()

    state = %{
      "bad\0key" => "x",
      "bad_value" => "x\0y",
      "duration" => struct(Duration),
      "encoded_struct" => %ValidJasonStruct{name: "x\0y", count: 2},
      "keep" => %{"ok" => true}
    }

    assert :ok = Store.save(id, state, [])

    assert {:ok,
            %{
              "encoded_struct" => %{"count" => 2},
              "keep" => %{"ok" => true}
            }} = Store.load(id, [])
  end

  test "save does not expose a session id or persistence exception" do
    id = "private-session-id"
    Application.put_env(:anubis_mcp, :session_store, repo: FailingRepo)

    log =
      ExUnit.CaptureLog.capture_log(fn ->
        assert {:error, :persistence_failed} = Store.save(id, %{"secret" => "private-state"}, [])
      end)

    assert log =~ "MCP session persistence failed"
    refute log =~ id
    refute log =~ "private-persistence-sentinel"
    refute log =~ "private-state"
  end

  test "save upserts on session_id (last write wins)" do
    id = sid()
    assert :ok = Store.save(id, %{"v" => 1}, [])
    assert :ok = Store.save(id, %{"v" => 2}, [])
    assert {:ok, %{"v" => 2}} = Store.load(id, [])
  end

  test "load returns :not_found for an unknown session" do
    assert {:error, :not_found} = Store.load(sid(), [])
  end

  test "load reaps an expired row lazily and reports :not_found" do
    id = sid()
    assert :ok = Store.save(id, %{"v" => 1}, ttl: -1_000)
    assert {:error, :not_found} = Store.load(id, [])
    # and it's gone
    assert {:error, :not_found} = Store.load(id, [])
  end

  test "delete removes the row" do
    id = sid()
    assert :ok = Store.save(id, %{"v" => 1}, [])
    assert :ok = Store.delete(id, [])
    assert {:error, :not_found} = Store.load(id, [])
  end

  test "list_active returns only non-expired session ids" do
    live = sid()
    dead = sid()
    assert :ok = Store.save(live, %{"v" => 1}, [])
    assert :ok = Store.save(dead, %{"v" => 1}, ttl: -1_000)

    {:ok, ids} = Store.list_active([])
    assert live in ids
    refute dead in ids
  end

  test "update_ttl extends a live session and 404s an unknown one" do
    id = sid()
    assert :ok = Store.save(id, %{"v" => 1}, ttl: 1_000)
    assert :ok = Store.update_ttl(id, 60_000, [])
    assert {:ok, _} = Store.load(id, [])
    assert {:error, :not_found} = Store.update_ttl(sid(), 60_000, [])
  end

  test "update read-modify-writes the stored state (string keys)" do
    id = sid()
    assert :ok = Store.save(id, %{"a" => 1}, [])
    assert :ok = Store.update(id, %{b: 2}, [])
    assert {:ok, %{"a" => 1, "b" => 2}} = Store.load(id, [])
  end

  test "update 404s an unknown session" do
    assert {:error, :not_found} = Store.update(sid(), %{a: 1}, [])
  end

  test "update_ttl does not revive an expired (not-yet-reaped) session" do
    id = sid()
    assert :ok = Store.save(id, %{"v" => 1}, ttl: -1_000)
    assert {:error, :not_found} = Store.update_ttl(id, 60_000, [])
  end

  test "update does not revive an expired session" do
    id = sid()
    assert :ok = Store.save(id, %{"v" => 1}, ttl: -1_000)
    assert {:error, :not_found} = Store.update(id, %{b: 2}, [])
  end

  test "load does not delete a row a concurrent save refreshed (guarded reap)" do
    id = sid()
    # Persist an already-expired row, then refresh it live before load reaps it.
    assert :ok = Store.save(id, %{"v" => 1}, ttl: -1_000)
    assert :ok = Store.save(id, %{"v" => 2}, ttl: 60_000)
    # load sees the live row; its expiry guard means it never deletes it.
    assert {:ok, %{"v" => 2}} = Store.load(id, [])
    assert {:ok, %{"v" => 2}} = Store.load(id, [])
  end

  test "cleanup_expired deletes only expired rows and returns the count" do
    live = sid()
    dead1 = sid()
    dead2 = sid()
    assert :ok = Store.save(live, %{}, [])
    assert :ok = Store.save(dead1, %{}, ttl: -1_000)
    assert :ok = Store.save(dead2, %{}, ttl: -1_000)

    assert {:ok, count} = Store.cleanup_expired([])
    assert count >= 2
    assert {:ok, _} = Store.load(live, [])
  end

  test "start_link is :ignore (stateless, no process)" do
    assert Store.start_link([]) == :ignore
  end

  defp with_isolated_migration_repo(fun) do
    schema = "attesto_mcp_rename_#{System.unique_integer([:positive])}"

    config =
      TestRepo.config()
      |> Keyword.merge(
        name: nil,
        pool: DBConnection.ConnectionPool,
        pool_size: 1,
        prepare: :unnamed
      )

    {:ok, repo_pid} = TestRepo.start_link(config)
    previous_repo = TestRepo.put_dynamic_repo(repo_pid)

    try do
      TestRepo.checkout(fn ->
        TestRepo.query!(~s(CREATE SCHEMA "#{schema}"))
        TestRepo.query!(~s(SET search_path TO "#{schema}"))

        try do
          fun.()
        after
          TestRepo.query!(~s(DROP SCHEMA "#{schema}" CASCADE))
        end
      end)
    after
      TestRepo.put_dynamic_repo(previous_repo)
      Supervisor.stop(repo_pid)
    end
  end

  defp create_isolated_current_session_table do
    TestRepo.query!("""
    CREATE TABLE attesto_mcp_anubis_sessions (
      session_id varchar(255) CONSTRAINT attesto_mcp_anubis_sessions_pkey PRIMARY KEY,
      state jsonb NOT NULL,
      expires_at timestamp(6) without time zone NOT NULL,
      inserted_at timestamp(6) without time zone NOT NULL,
      updated_at timestamp(6) without time zone NOT NULL
    )
    """)

    TestRepo.query!("""
    CREATE INDEX attesto_mcp_anubis_sessions_expires_at_index
    ON attesto_mcp_anubis_sessions (expires_at)
    """)
  end

  defp rename_anubis_table_up do
    TestRepo.query!("ALTER TABLE attesto_mcp_sessions RENAME TO attesto_mcp_anubis_sessions")

    TestRepo.query!("""
    ALTER TABLE attesto_mcp_anubis_sessions
    RENAME CONSTRAINT attesto_mcp_sessions_pkey
    TO attesto_mcp_anubis_sessions_pkey
    """)

    TestRepo.query!("""
    ALTER INDEX attesto_mcp_sessions_expires_at_index
    RENAME TO attesto_mcp_anubis_sessions_expires_at_index
    """)
  end

  defp rename_anubis_table_down do
    TestRepo.query!("""
    ALTER INDEX attesto_mcp_anubis_sessions_expires_at_index
    RENAME TO attesto_mcp_sessions_expires_at_index
    """)

    TestRepo.query!("""
    ALTER TABLE attesto_mcp_anubis_sessions
    RENAME CONSTRAINT attesto_mcp_anubis_sessions_pkey
    TO attesto_mcp_sessions_pkey
    """)

    TestRepo.query!("ALTER TABLE attesto_mcp_anubis_sessions RENAME TO attesto_mcp_sessions")
  end
end

defmodule AttestoMCP.Anubis.SessionStore.EctoBoundaryTest do
  @moduledoc false
  use ExUnit.Case, async: false

  alias AttestoMCP.Anubis.SessionStore.Ecto, as: Store
  alias AttestoMCP.Anubis.SessionStore.EctoTest.FailingRepo

  setup do
    previous = Application.get_env(:anubis_mcp, :session_store)
    Application.put_env(:anubis_mcp, :session_store, repo: FailingRepo, json_library: Jason)

    on_exit(fn ->
      if previous,
        do: Application.put_env(:anubis_mcp, :session_store, previous),
        else: Application.delete_env(:anubis_mcp, :session_store)
    end)
  end

  test "malformed session identifiers never reach the Repo" do
    invalid_ids = [nil, "", "contains space", "nul\0id", <<0xFF>>, String.duplicate("a", 256)]

    for id <- invalid_ids do
      ExUnit.CaptureLog.capture_log(fn ->
        assert {:error, :persistence_failed} = Store.save(id, %{}, [])
      end)

      assert {:error, :not_found} = Store.load(id, [])
      assert :ok = Store.delete(id, [])
      assert {:error, :not_found} = Store.update_ttl(id, 1_000, [])
      assert {:error, :not_found} = Store.update(id, %{}, [])
    end
  end

  test "all Repo exceptions become one redacted persistence error" do
    id = "private-session-id"

    log =
      ExUnit.CaptureLog.capture_log(fn ->
        assert {:error, :persistence_failed} = Store.save(id, %{"secret" => "state"}, [])
        assert {:error, :persistence_failed} = Store.load(id, [])
        assert {:error, :persistence_failed} = Store.delete(id, [])
        assert {:error, :persistence_failed} = Store.list_active([])
        assert {:error, :persistence_failed} = Store.update_ttl(id, 1_000, [])
        assert {:error, :persistence_failed} = Store.update(id, %{}, [])
        assert {:error, :persistence_failed} = Store.cleanup_expired([])
      end)

    assert log =~ "MCP session persistence failed"
    refute log =~ id
    refute log =~ "private-persistence-sentinel"
    refute log =~ "secret"
  end
end
