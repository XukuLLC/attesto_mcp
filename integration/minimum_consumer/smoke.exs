import Plug.Conn
import Plug.Test

alias AttestoMCP.MinimumConsumer.Router

Application.put_env(:phoenix, :json_library, JSON)

defmodule AttestoMCP.MinimumConsumer.Router do
  use Phoenix.Router
  use AttestoMCP.Router

  scope "/" do
    attesto_mcp_protected_resource_metadata "/mcp",
      scopes: [AttestoMCP.Scopes.tools_call()]
  end
end

conn =
  :get
  |> conn("https://mcp.example.com/.well-known/oauth-protected-resource/mcp")
  |> put_req_header("accept", "application/json")
  |> Router.call(Router.init([]))

metadata = JSON.decode!(conn.resp_body)

if !(conn.status == 200 and
       metadata["resource"] == "https://mcp.example.com/mcp" and
       metadata["authorization_servers"] == ["https://mcp.example.com"] and
       AttestoMCP.Scopes.tools_call() in metadata["scopes_supported"]) do
  raise "minimum-version consumer returned invalid RFC 9728 metadata: #{inspect(conn.status)} #{inspect(metadata)}"
end
