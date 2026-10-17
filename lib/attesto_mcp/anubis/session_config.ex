defmodule AttestoMCP.Anubis.SessionConfig do
  @moduledoc false

  @default_ttl_ms 1_800_000

  @spec default_ttl_ms() :: pos_integer()
  def default_ttl_ms, do: @default_ttl_ms

  @spec json_library() :: module()
  def json_library, do: Application.get_env(:postgrex, :json_library, Jason)
end
