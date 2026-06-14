defmodule AttestoMCP.Plug.ProtectResource do
  @moduledoc """
  Protect an HTTP MCP endpoint in one plug.

  The MCP authorization spec treats a protected HTTP MCP server as an OAuth
  resource server (RFC 9728). Guarding such an endpoint correctly takes two
  ordered steps: authenticate the access token (and any DPoP/mTLS sender
  constraint), then enforce the scopes the route requires. `ProtectResource`
  composes `AttestoMCP.Plug.Authenticate` followed by
  `AttestoMCP.Plug.RequireScopes` into a single, correctly ordered,
  halt-respecting pipeline so the host does not hand-wire and re-order the two
  plugs (and the WWW-Authenticate `resource_metadata` challenge) on every
  route.

      plug AttestoMCP.Plug.ProtectResource,
        config: &MyApp.Attesto.config/0,
        replay_check: &MyApp.DPoPReplay.check_and_record/2,
        resource: "/mcp",
        scopes: [AttestoMCP.Scopes.tools_call()]

  `init/1` returns no closures, so the plug works as a compile-time router
  pipeline plug (`plug_init_mode: :compile`, the production default). As Plug
  requires under `:compile` mode, any callback the host passes (`:config`,
  `:replay_check`, `:send_error`, …) must be a remote capture (`&Mod.fun/n`) or
  an MFA tuple (`{Mod, :fun}`), not an anonymous `fn`.

  This is exactly equivalent to:

      plug AttestoMCP.Plug.Authenticate,
        config: &MyApp.Attesto.config/0,
        replay_check: &MyApp.DPoPReplay.check_and_record/2,
        resource_path: "/mcp"

      plug AttestoMCP.Plug.RequireScopes,
        scopes: [AttestoMCP.Scopes.tools_call()]

  ## Options

    * `:scopes` (or `:scope`) - the scope(s) the route requires, forwarded to
      `AttestoMCP.Plug.RequireScopes`. At least one scope is required.
    * `:resource` (or `:resource_path`) - the MCP endpoint path, for example
      `"/mcp"` or `"/mcp/brokers"`. It drives the RFC 9728 `resource_metadata`
      auth-param appended to `WWW-Authenticate` challenges, derived from the
      live request origin via `AttestoMCP.Metadata.protected_resource_url/2`.
      Both names mean the same thing; `:resource` reads naturally here while
      `:resource_path` matches `AttestoMCP.Plug.Authenticate`.
    * `:base_url` (or `:origin`) - pin the origin of the `resource_metadata`
      challenge URL behind a TLS-terminating proxy (a `String.t()` or
      `(conn -> url)`), instead of trusting the proxy-rewritten request. When
      omitted, the live request origin is used. This keeps the challenge URL
      aligned with a pinned metadata `resource` and closes the
      `X-Forwarded-Host` spoofing vector. See `guides/proxy_origin.md`.

  Every other option is passed through to `AttestoMCP.Plug.Authenticate`:
  `:config`, `:replay_check`, `:nonce_check`, `:nonce_issue`, `:cert_der`,
  `:htu`, `:credential_from_conn`, `:send_error`, `:www_authenticate`,
  `:no_store`, `:principal`, `:principal_key`, `:claims_key`, `:scopes_key`,
  `:sender_key`, and `:resource_metadata_url`. The transport hooks
  (`:send_error`, `:www_authenticate`) and the assign keys (`:claims_key`,
  `:scopes_key`) are also shared with `AttestoMCP.Plug.RequireScopes` so a
  scope rejection renders through the same host-controlled error envelope.
  """

  @behaviour Plug

  alias AttestoMCP.Plug.Authenticate
  alias AttestoMCP.Plug.RequireScopes

  # Options that RequireScopes consumes. The scope set is its own; the rest are
  # shared with Authenticate so both steps render through one error envelope and
  # read the same assigns.
  @scope_keys [:scope, :scopes]
  @shared_keys [:send_error, :www_authenticate, :claims_key, :scopes_key]

  # The escape-safe inputs (strings / atoms / `{m, f}` tuples - never a closure)
  # RequireScopes needs to derive the same RFC 9728 `resource_metadata` challenge
  # Authenticate uses. `:www_authenticate` is deliberately excluded: a host
  # override is already carried in the RequireScopes transport (via `@shared_keys`)
  # and wins there, so it never needs to be re-derived here.
  @metadata_keys [:resource_metadata_url, :resource_path, :base_url, :origin]

  @impl Plug
  def init(opts) when is_list(opts) do
    %{
      authenticate: Authenticate.init(authenticate_opts(opts)),
      require_scopes: RequireScopes.init(require_scopes_opts(opts)),
      # Escape-safe spec used to build the scope-rejection `resource_metadata`
      # challenge at CALL time. Baking the generated `:www_authenticate` closure
      # into init/1 would make the result non-escapable, so the plug could not be
      # used as a compile-time router pipeline plug (`plug_init_mode: :compile`).
      metadata_challenge: metadata_challenge_opts(opts)
    }
  end

  @impl Plug
  def call(conn, %{authenticate: authenticate, require_scopes: require_scopes, metadata_challenge: metadata_challenge}) do
    conn = Authenticate.call(conn, authenticate)

    if conn.halted do
      conn
    else
      RequireScopes.call(conn, put_metadata_challenge(require_scopes, metadata_challenge))
    end
  end

  defp authenticate_opts(opts) do
    opts
    |> Keyword.drop(@scope_keys)
    |> rename_resource()
  end

  defp require_scopes_opts(opts) do
    Keyword.take(opts, @scope_keys ++ @shared_keys)
  end

  defp metadata_challenge_opts(opts) do
    opts
    |> rename_resource()
    |> Keyword.take(@metadata_keys)
  end

  # At CALL time, build the generated `resource_metadata` challenge from the
  # escape-safe spec and inject it into the RequireScopes transport, so an
  # insufficient_scope 403 points the client at metadata too. `put_new` means a
  # host-supplied `:www_authenticate` (already in the transport) wins.
  defp put_metadata_challenge(require_scopes, metadata_challenge) do
    case Authenticate.metadata_www_authenticate(metadata_challenge) do
      nil ->
        require_scopes

      www_authenticate ->
        Map.update(
          require_scopes,
          :transport,
          [www_authenticate: www_authenticate],
          &Keyword.put_new(&1, :www_authenticate, www_authenticate)
        )
    end
  end

  defp rename_resource(opts) do
    case Keyword.fetch(opts, :resource) do
      {:ok, resource} ->
        opts
        |> Keyword.delete(:resource)
        |> Keyword.put_new(:resource_path, resource)

      :error ->
        opts
    end
  end
end
