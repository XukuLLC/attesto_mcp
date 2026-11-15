defmodule AttestoMCP.Scopes do
  @moduledoc """
  MCP-oriented scope naming conventions.

  These helpers are deliberately small string builders. They do not decide
  which principal is allowed to hold a scope, and they do not require a server
  to use this catalog. The host authorization server remains responsible for
  issuing scopes and the host MCP server remains responsible for selecting
  which scopes protect each operation.
  """

  @tools_read "mcp:tools:read"
  @tools_call "mcp:tools:call"
  @resources_read "mcp:resources:read"
  @prompts_read "mcp:prompts:read"

  @doc "Scope convention for listing or reading MCP tool definitions."
  @spec tools_read() :: String.t()
  def tools_read, do: @tools_read

  @doc "Scope convention for invoking MCP tools."
  @spec tools_call() :: String.t()
  def tools_call, do: @tools_call

  @doc "Scope convention for reading MCP resources."
  @spec resources_read() :: String.t()
  def resources_read, do: @resources_read

  @doc "Scope convention for reading MCP prompts."
  @spec prompts_read() :: String.t()
  def prompts_read, do: @prompts_read

  @doc "The default generic MCP scope conventions."
  @spec all() :: [String.t()]
  def all, do: [tools_read(), tools_call(), resources_read(), prompts_read()]

  @doc """
  Prefix the generic scope suffix with a server-specific namespace.

      iex> AttestoMCP.Scopes.server("search", :tools_call)
      "search:mcp:tools:call"
  """
  @spec server(String.t(), atom() | String.t()) :: String.t()
  def server(prefix, scope) when is_binary(prefix) do
    prefix <> ":" <> normalize(scope)
  end

  @doc "Reject `offline_access` on MCP protected-resource metadata or challenges (MCP 2026-07-28)."
  @spec reject_offline_access!([String.t()], String.t()) :: :ok
  def reject_offline_access!(scopes, context \\ "MCP protected resource") when is_list(scopes) do
    if "offline_access" in scopes do
      raise ArgumentError,
            "#{context} must not include offline_access (refresh tokens are not a resource requirement per MCP 2026-07-28)"
    end

    :ok
  end

  defp normalize(:tools_read), do: tools_read()
  defp normalize(:tools_call), do: tools_call()
  defp normalize(:resources_read), do: resources_read()
  defp normalize(:prompts_read), do: prompts_read()
  defp normalize(scope) when is_binary(scope), do: scope
end
