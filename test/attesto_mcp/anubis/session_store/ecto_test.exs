defmodule AttestoMCP.Anubis.SessionStore.EctoTest.BareStruct do
  @moduledoc false
  defstruct [:x]
end

defmodule AttestoMCP.Anubis.SessionStore.EctoTest do
  @moduledoc """
  Behaviour-conformance tests for the Postgres-backed
  `Anubis.Server.Session.Store` adapter. Tagged `:ecto` so the suite runs only
  when a SQL backend is available.
  """
  use ExUnit.Case, async: true

  alias AttestoMCP.Anubis.SessionStore.Ecto, as: Store
  alias AttestoMCP.Anubis.SessionStore.EctoTest.BareStruct
  alias AttestoMCP.TestRepo
  alias Ecto.Adapters.SQL.Sandbox

  @moduletag :ecto

  setup do
    :ok = Sandbox.checkout(TestRepo)
  end

  defp sid, do: "sess-#{System.unique_integer([:positive])}"

  test "save then load round-trips the state (string-keyed)" do
    id = sid()
    assert :ok = Store.save(id, %{"client_info" => %{"name" => "c"}, "n" => 1}, [])
    assert {:ok, %{"client_info" => %{"name" => "c"}, "n" => 1}} = Store.load(id, [])
  end

  test "save sanitizes non-encodable values before the jsonb insert (no crash)" do
    id = sid()
    # A bare struct + a pid would otherwise raise in the driver and kill the session.
    assert :ok = Store.save(id, %{"user" => %BareStruct{x: 1}, "pid" => self(), "keep" => "v"}, [])
    assert {:ok, state} = Store.load(id, [])
    assert state == %{"keep" => "v"}
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
end
