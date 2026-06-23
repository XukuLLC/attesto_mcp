defmodule AttestoMCP.Anubis.Registry.HordeTest do
  @moduledoc false
  use ExUnit.Case, async: false

  alias AttestoMCP.Anubis.Registry.Horde, as: Registry

  setup do
    name = :"attesto_mcp_test_reg_#{System.unique_integer([:positive])}"
    start_supervised!(%{id: name, start: {Horde.Registry, :start_link, [[name: name, keys: :unique, members: :auto]]}})
    {:ok, registry: name}
  end

  test "session_name/2 returns a :via tuple keyed on the raw session id (no atom derived)", %{registry: reg} do
    assert Registry.session_name(reg, "sess-123") == {:via, Horde.Registry, {reg, "sess-123"}}
  end

  test "a process started under the :via name is found by lookup_session/2", %{registry: reg} do
    via = Registry.session_name(reg, "sess-1")
    {:ok, pid} = Agent.start_link(fn -> :state end, name: via)

    assert {:ok, ^pid} = Registry.lookup_session(reg, "sess-1")
  end

  test "lookup_session/2 returns :not_found for an unknown session", %{registry: reg} do
    assert {:error, :not_found} = Registry.lookup_session(reg, "nope")
  end

  test "the entry is dropped when the owning process exits", %{registry: reg} do
    via = Registry.session_name(reg, "sess-2")
    {:ok, pid} = Agent.start(fn -> :state end, name: via)
    assert {:ok, ^pid} = Registry.lookup_session(reg, "sess-2")

    ref = Process.monitor(pid)
    Agent.stop(pid)
    assert_receive {:DOWN, ^ref, :process, ^pid, _}, 1_000

    # Horde removes the CRDT entry asynchronously on the owner's exit.
    Enum.reduce_while(1..50, nil, fn _i, _acc ->
      case Registry.lookup_session(reg, "sess-2") do
        {:error, :not_found} -> {:halt, :ok}
        {:ok, _} -> Process.sleep(20) && {:cont, nil}
      end
    end)

    assert {:error, :not_found} = Registry.lookup_session(reg, "sess-2")
  end

  test "register_session/3 and unregister_session/2 are no-ops (registration rides the :via name)", %{registry: reg} do
    assert Registry.register_session(reg, "x", self()) == :ok
    assert Registry.unregister_session(reg, "x") == :ok
  end
end
