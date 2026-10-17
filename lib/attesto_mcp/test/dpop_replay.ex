defmodule AttestoMCP.Test.DPoPReplay do
  @moduledoc """
  Minimal DPoP replay callback for tests.

  Production systems should use a shared store for every MCP server instance.
  This helper is node-local, is owned by the process that creates the callback,
  and exists only to make replay behavior explicit in tests and examples.
  """

  @doc """
  Return a `replay_check` callback compatible with `Attesto.DPoP.verify_proof/2`.
  """
  @spec callback() :: (String.t(), pos_integer() -> :ok | {:error, :replay})
  def callback do
    table = :ets.new(__MODULE__, [:set, :public, write_concurrency: true])

    fn jti, _ttl ->
      case :ets.insert_new(table, {jti, true}) do
        true -> :ok
        false -> {:error, :replay}
      end
    end
  end
end
