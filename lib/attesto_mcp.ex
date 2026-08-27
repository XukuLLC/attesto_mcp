defmodule AttestoMCP do
  @moduledoc """
  Authentication helpers for HTTP-based Model Context Protocol servers.

  `attesto_mcp` does not implement the Model Context Protocol. It wraps
  Plug/Phoenix endpoints that already speak MCP and connects them to Attesto's
  OAuth/OIDC verifier, DPoP proof verification, mTLS token binding, scope
  algebra, and metadata builders.

  For a complete Attesto-native implementation, use
  [`attesto_mcp_server`](https://hexdocs.pm/attesto_mcp_server). Use this package
  directly when integrating an existing MCP transport or implementing a custom
  HTTP boundary.
  """
end
