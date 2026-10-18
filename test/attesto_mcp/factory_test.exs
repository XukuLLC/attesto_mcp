defmodule AttestoMCP.Test.FactoryTest do
  @moduledoc false
  use ExUnit.Case, async: false

  alias Attesto.Keystore.Static
  alias AttestoMCP.Test.Factory

  setup do
    previous = Application.fetch_env(:attesto, Static)
    on_exit(fn -> restore_static_config(previous) end)
    :ok
  end

  test "config leaves application state unchanged when called outside an ExUnit test process" do
    sentinel = [signing_pem: "existing"]
    Application.put_env(:attesto, Static, sentinel)

    result =
      Task.async(fn ->
        try do
          Factory.config()
          :returned
        rescue
          error in ArgumentError -> {:raised, error}
        end
      end)
      |> Task.await()

    assert {:raised, %ArgumentError{}} = result
    assert Application.fetch_env(:attesto, Static) == {:ok, sentinel}
  end

  test "config restores an existing static-keystore setting on exit" do
    sentinel = [signing_pem: "existing"]
    Application.put_env(:attesto, Static, sentinel)

    on_exit(fn -> assert Application.fetch_env(:attesto, Static) == {:ok, sentinel} end)

    assert %Attesto.Config{} = Factory.config()
    refute Application.get_env(:attesto, Static) == sentinel
  end

  test "config deletes its static-keystore setting on exit when none existed" do
    Application.delete_env(:attesto, Static)

    on_exit(fn -> assert Application.fetch_env(:attesto, Static) == :error end)

    assert %Attesto.Config{} = Factory.config()
    assert {:ok, _fixture_config} = Application.fetch_env(:attesto, Static)
  end

  defp restore_static_config({:ok, config}), do: Application.put_env(:attesto, Static, config)
  defp restore_static_config(:error), do: Application.delete_env(:attesto, Static)
end
