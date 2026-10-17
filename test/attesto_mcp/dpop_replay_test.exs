defmodule AttestoMCP.Test.DPoPReplayTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias AttestoMCP.Test.DPoPReplay

  test "the test callback works across request processes" do
    replay_check = DPoPReplay.callback()

    assert :ok == Task.async(fn -> replay_check.("proof-1", 60) end) |> Task.await()

    assert {:error, :replay} ==
             Task.async(fn -> replay_check.("proof-1", 60) end) |> Task.await()
  end
end
