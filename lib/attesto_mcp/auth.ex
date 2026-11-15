defmodule AttestoMCP.Auth do
  @moduledoc "Authentication context helpers; MFA extras follow the call arguments."
  defdelegate scopes(value), to: Attesto.ResourceContext
  defdelegate scheme(claims), to: Attesto.ResourceContext
  defdelegate invoke(callback, args), to: Attesto.ResourceContext
  @doc false
  def with_resource_errors(fun) do
    fun.()
  rescue
    error in ArgumentError ->
      message =
        error.message
        |> String.replace("Attesto.Plug.ResourceAuthenticate", "AttestoMCP.Plug.Authenticate")
        |> String.replace("Attesto.Plug.ResourceScopes", "AttestoMCP.Plug.RequireScopes")
        |> String.replace("a resource audience policy", "an MCP audience policy")

      reraise %{error | message: message}, __STACKTRACE__
  end
end
