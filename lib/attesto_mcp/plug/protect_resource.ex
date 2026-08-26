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

  ## Dynamically classified requests

  Some protected resources cannot know the required scope until a bounded
  request envelope has been classified. For that case, use the explicit
  two-phase API:

      protection =
        AttestoMCP.Plug.ProtectResource.prepare(
          config: &MyApp.Attesto.config/0,
          resource: "/mcp"
        )

      conn = AttestoMCP.Plug.ProtectResource.authenticate(conn, protection)

      if conn.halted do
        conn
      else
        # Classify only bounded, side-effect-free request metadata here.
        scopes = scopes_for_request(conn)
        conn = AttestoMCP.Plug.ProtectResource.authorize(conn, protection, scopes)

        if conn.halted, do: conn, else: dispatch(conn)
      end

  `authenticate/2` performs the token and sender-constraint verification once.
  It also binds the authenticated connection to that prepared boundary, so
  `authorize/3` rejects a connection authenticated by a different boundary or
  one carrying only pre-existing assigns. `authorize/3` then consumes the
  verified assigns and enforces the supplied scopes through `RequireScopes`.
  An empty scope list means the classified operation requires authentication
  but no additional OAuth scope. The host MUST call `authorize/3` before
  dispatch; a prepared split boundary is deliberately not accepted by `call/2`.

  ## Options

    * `:scopes` (or `:scope`) - the scope(s) a normal Plug route requires,
      forwarded to `AttestoMCP.Plug.RequireScopes`. At least one scope is
      required by `init/1`; omit this option from `prepare/1` and supply the
      classified list to `authorize/3` instead.
    * `:step_up` - an optional RFC 9470 step-up requirement for the route
      (`[acr_values: ["phr"], max_age: 300]` or an
      `%Attesto.StepUp.Requirement{}`). After the token is verified, its
      `acr` / `auth_time` claims must satisfy the requirement or the request is
      refused 401 `insufficient_user_authentication`, naming the `acr_values` /
      `max_age` the client must re-request at the authorization endpoint. A
      token from a machine grant (no `auth_time`) always challenges a freshness
      requirement, so step-up routes are for end-user grants.
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
    * `:resource_audience` - confines access tokens to this protected resource;
      `:resource` derives its audience identifier from the resource path and
      resolved origin. A scalar token audience must match, and every member of
      an array-valued audience must match. This option is mutually exclusive
      with Attesto core's `:trusted_audiences`; configuring both raises.

  Every other option is passed through to `AttestoMCP.Plug.Authenticate`:
  `:config`, `:replay_check`, `:nonce_check`, `:nonce_issue`, `:cert_der`,
  `:trusted_audiences`, `:htu`, `:credential_from_conn`, `:bearer_methods`, `:send_error`,
  `:www_authenticate`, `:no_store`, `:principal`, `:principal_key`,
  `:claims_key`, `:scopes_key`, `:sender_key`, and `:resource_metadata_url`.
  MCP defaults to `bearer_methods: [:header]`; set
  `bearer_methods: [:header, :body]` only when the resource intentionally
  accepts RFC 6750 §2.2 form-body access tokens. The transport hooks
  (`:send_error`, `:www_authenticate`, `:no_store`) and the assign keys
  (`:claims_key`, `:scopes_key`) are also shared with
  `AttestoMCP.Plug.RequireScopes` so a scope rejection renders through the same
  host-controlled error envelope.
  """

  @behaviour Plug

  alias Attesto.Plug.OAuthError
  alias Attesto.Scope
  alias AttestoMCP.Plug.Authenticate
  alias AttestoMCP.Plug.RequireScopes

  @boundary_private_key :attesto_mcp_protect_resource_boundary

  @typedoc "An opaque, prepared protected-resource boundary."
  @opaque protection :: %{
            required(:authenticate) => keyword(),
            required(:boundary_id) => binary(),
            required(:metadata_challenge) => keyword(),
            required(:require_scopes) => nil,
            required(:scope_opts) => keyword()
          }

  # Options that RequireScopes consumes. The scope set is its own; the rest are
  # shared with Authenticate so both steps render through one error envelope and
  # read the same assigns.
  @scope_keys [:scope, :scopes]
  @shared_keys [:send_error, :www_authenticate, :no_store, :claims_key, :scopes_key]

  # The escape-safe inputs (strings / atoms / `{m, f}` tuples - never a closure)
  # RequireScopes needs to derive the same RFC 9728 `resource_metadata` challenge
  # Authenticate uses. `:www_authenticate` is deliberately excluded: a host
  # override is already carried in the RequireScopes transport (via `@shared_keys`)
  # and wins there, so it never needs to be re-derived here.
  @metadata_keys [:resource_metadata_url, :resource_path, :base_url, :origin]

  @impl Plug
  def init(opts) when is_list(opts) do
    opts
    |> build_protection()
    |> Map.put(:require_scopes, RequireScopes.init(require_scopes_opts(opts)))
  end

  @impl Plug
  def call(_conn, %{require_scopes: nil}) do
    raise ArgumentError,
          "a split ProtectResource boundary must call authenticate/2 and authorize/3 explicitly"
  end

  def call(conn, %{require_scopes: require_scopes, metadata_challenge: metadata_challenge} = protection) do
    conn = authenticate(conn, protection)

    if conn.halted do
      conn
    else
      RequireScopes.call(conn, put_metadata_challenge(require_scopes, metadata_challenge))
    end
  end

  @doc "Prepares an authentication-first boundary whose scopes are supplied to `authorize/3`."
  @spec prepare(keyword()) :: protection()
  def prepare(opts) when is_list(opts) do
    if Enum.any?(@scope_keys, &Keyword.has_key?(opts, &1)) do
      raise ArgumentError,
            "prepare/1 accepts dynamic scopes only; pass the required scopes to authorize/3"
    end

    opts
    |> build_protection()
    |> Map.put(:boundary_id, :crypto.strong_rand_bytes(32))
  end

  defp build_protection(opts) do
    %{
      authenticate: Authenticate.init(authenticate_opts(opts)),
      require_scopes: nil,
      scope_opts: Keyword.take(opts, @shared_keys),
      # Escape-safe spec used to build the scope-rejection `resource_metadata`
      # challenge at CALL time. Baking the generated `:www_authenticate` closure
      # into init/1 would make the result non-escapable, so the plug could not be
      # used as a compile-time router pipeline plug (`plug_init_mode: :compile`).
      metadata_challenge: metadata_challenge_opts(opts)
    }
  end

  @doc "Authenticates a request through a prepared ProtectResource boundary."
  @spec authenticate(Plug.Conn.t(), protection() | map()) :: Plug.Conn.t()
  def authenticate(conn, %{authenticate: authenticate} = protection) do
    conn =
      conn
      |> Plug.Conn.put_private(@boundary_private_key, nil)
      |> Authenticate.call(authenticate)

    if conn.halted do
      conn
    else
      mark_boundary_authenticated(conn, protection)
    end
  end

  @doc "Enforces dynamically selected scopes after `authenticate/2` and before dispatch."
  @spec authorize(Plug.Conn.t(), protection(), [String.t()]) :: Plug.Conn.t()
  def authorize(conn, protection, scopes) when is_list(scopes) do
    validate_dynamic_scopes!(scopes)

    cond do
      conn.halted ->
        conn

      not boundary_authenticated?(conn, protection) ->
        reject_unbound_connection(conn, protection)

      scopes == [] ->
        conn

      true ->
        require_scopes =
          protection.scope_opts
          |> Keyword.put(:scopes, scopes)
          |> RequireScopes.init()
          |> put_metadata_challenge(protection.metadata_challenge)

        RequireScopes.call(conn, require_scopes)
    end
  end

  def authorize(_conn, _protection, _scopes) do
    raise ArgumentError, "dynamic scopes must be unique RFC 6749 scope-token strings"
  end

  defp validate_dynamic_scopes!(scopes) do
    if not Scope.valid_list?(scopes) or Enum.uniq(scopes) != scopes do
      raise ArgumentError, "dynamic scopes must be unique RFC 6749 scope-token strings"
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
    Map.update(
      require_scopes,
      :transport,
      metadata_transport([], metadata_challenge),
      &metadata_transport(&1, metadata_challenge)
    )
  end

  defp metadata_transport(transport, metadata_challenge) do
    case Authenticate.metadata_www_authenticate(metadata_challenge) do
      nil ->
        transport

      www_authenticate ->
        Keyword.put_new(transport, :www_authenticate, www_authenticate)
    end
  end

  defp mark_boundary_authenticated(conn, %{boundary_id: boundary_id}) when is_binary(boundary_id),
    do: Plug.Conn.put_private(conn, @boundary_private_key, boundary_id)

  defp mark_boundary_authenticated(conn, _protection), do: conn

  defp boundary_authenticated?(conn, %{boundary_id: boundary_id}) when is_binary(boundary_id),
    do: conn.private[@boundary_private_key] == boundary_id

  defp boundary_authenticated?(_conn, _protection), do: false

  defp reject_unbound_connection(conn, protection) do
    claims_key = Keyword.get(protection.scope_opts, :claims_key, :attesto_mcp_claims)

    transport =
      protection.scope_opts
      |> Keyword.take([:send_error, :www_authenticate, :no_store])
      |> metadata_transport(protection.metadata_challenge)

    OAuthError.unauthorized(
      conn,
      scheme_of(conn.assigns[claims_key]),
      "invalid_token",
      Keyword.put(transport, :description, "request was not authenticated by this protected-resource boundary")
    )
  end

  defp scheme_of(%{"cnf" => %{"jkt" => jkt}}) when is_binary(jkt), do: :dpop
  defp scheme_of(_claims), do: :bearer

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
