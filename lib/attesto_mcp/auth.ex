defmodule AttestoMCP.Auth do
  @moduledoc false

  alias Attesto.Scope

  @spec scopes(term()) :: [String.t()]
  def scopes(%{"scope" => scope}) when is_binary(scope), do: Scope.parse(scope, whitespace: :ascii_whitespace)

  def scopes(scopes) when is_list(scopes), do: scopes
  def scopes(_value), do: []

  @spec scheme(term()) :: :bearer | :dpop
  def scheme(%{"cnf" => %{"jkt" => jkt}}) when is_binary(jkt), do: :dpop
  def scheme(_claims), do: :bearer

  @spec invoke(term(), [term()]) :: term()
  def invoke(fun, args) when is_function(fun), do: apply(fun, args)
  def invoke({module, fun}, args) when is_atom(module) and is_atom(fun), do: apply(module, fun, args)

  def invoke({module, fun, extra}, args) when is_atom(module) and is_atom(fun) and is_list(extra),
    do: apply(module, fun, args ++ extra)

  def invoke(_callback, _args), do: nil
end
