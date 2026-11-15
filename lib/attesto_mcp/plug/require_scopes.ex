defmodule AttestoMCP.Plug.RequireScopes do
  @moduledoc """
  Require scopes on a request authenticated by `AttestoMCP.Plug.Authenticate`.

  The plug reads the verified scope list from `conn.assigns` and checks it with
  `Attesto.Scope` (the same scope algebra `Attesto.Plug.RequireScopes` uses). Routes choose their own required scopes; the MCP profile refuses
  `offline_access` because refresh-token privileges are not resource requirements.

      plug AttestoMCP.Plug.RequireScopes, scopes: [AttestoMCP.Scopes.tools_call()]

  Rejections are rendered through `Attesto.Plug.OAuthError`: a request that is
  not authenticated gets a 401 `invalid_token`, and an authenticated request
  that is missing a required scope gets a 403 `insufficient_scope` (RFC 6750
  §3.1). Both delegate to `Attesto.Plug.OAuthError`, threading the per-request
  `:www_authenticate` / `:send_error` transport hooks
  `AttestoMCP.Plug.ProtectResource` injects, so a scope rejection carries the
  same RFC 9728 `resource_metadata` challenge and host-controlled error envelope
  the authentication rejection does.

  This plug reads MCP-specific assign keys (`:attesto_mcp_claims` /
  `:attesto_mcp_scopes`, set by `AttestoMCP.Plug.Authenticate`) and a pre-split
  granted-scope list; that is why it is a thin wrapper over the OAuthError
  renderer rather than a direct use of `Attesto.Plug.RequireScopes` (which reads
  the `scope` claim under its own key).

  Every call is wrapped in the `[:attesto_mcp, :require_scopes]` telemetry
  span described in `AttestoMCP.Telemetry`.
  """

  @behaviour Plug

  alias Attesto.Plug.ResourceScopes
  alias AttestoMCP.Telemetry

  @impl Plug
  def init(opts) do
    opts = if Keyword.keyword?(opts), do: opts, else: [scopes: opts]

    prepared =
      AttestoMCP.Auth.with_resource_errors(fn ->
        opts
        |> Keyword.put_new(:claims_key, :attesto_mcp_claims)
        |> Keyword.put_new(:scopes_key, :attesto_mcp_scopes)
        |> Telemetry.wrap_send_error()
        |> ResourceScopes.init()
      end)

    AttestoMCP.Scopes.reject_offline_access!(prepared.required, "AttestoMCP.Plug.RequireScopes")
    prepared
  end

  @impl Plug
  def call(conn, opts) do
    Telemetry.span(:require_scopes, fn ->
      conn = ResourceScopes.call(conn, opts)
      {conn, Map.take(Telemetry.stop_metadata(conn), [:outcome, :status])}
    end)
  end
end
