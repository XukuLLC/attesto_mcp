ExUnit.start(autorun: false)

defmodule AttestoMCP.PackagedTestHelpersConsumerTest do
  use ExUnit.Case, async: false

  alias AttestoMCP.Test.DPoPAssertions
  alias AttestoMCP.Test.DPoPReplay
  alias AttestoMCP.Test.Factory

  test "the package exposes every downstream test helper after a production dependency build" do
    assert Code.ensure_loaded?(Factory)
    assert function_exported?(Factory, :config, 0)
    assert function_exported?(Factory, :access_token, 2)
    assert function_exported?(Factory, :dpop_proof, 2)

    assert Code.ensure_loaded?(DPoPReplay)
    assert function_exported?(DPoPReplay, :callback, 0)

    assert Code.ensure_loaded?(DPoPAssertions)
    assert function_exported?(DPoPAssertions, :assert_dpop_bound_bearer_rejected, 3)
    assert function_exported?(DPoPAssertions, :assert_dpop_proof_accepted, 3)

    assert %Attesto.Config{} = Factory.config()

    replay_check = DPoPReplay.callback()
    assert :ok == replay_check.("packaged-helper-proof", 60)
    assert {:error, :replay} == replay_check.("packaged-helper-proof", 60)
  end
end

result = ExUnit.run()

if result.failures != 0 do
  System.halt(1)
end
