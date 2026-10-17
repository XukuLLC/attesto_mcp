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
        resource_path: "/mcp",
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
          resource_path: "/mcp"
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
    * `:resource_path` - the MCP endpoint path, for example
      `"/mcp"` or `"/mcp/brokers"`. It drives the RFC 9728 `resource_metadata`
      auth-param appended to `WWW-Authenticate` challenges. The former
      `:resource` path alias is deprecated because metadata uses `:resource`
      for an absolute RFC 9728 resource identifier.
    * `:base_url` (or `:origin`) - pin the origin of the `resource_metadata`
      challenge URL behind a TLS-terminating proxy (a `String.t()` or
      `(conn -> url)`), instead of trusting the request authority. It is
      required with `resource_audience: :resource`. Invalid literals fail at
      initialization and invalid callback results fail at request time. See
      `guides/proxy_origin.md`.
    * `:allow_http` - permit an HTTP `resource_metadata` URL for a deliberate
      development endpoint. HTTPS remains the default.
    * `:resource_audience` - confines access tokens to this protected resource;
      `:resource` derives its audience identifier from the resource path and
      resolved origin. A scalar token audience must match, and every member of
      an array-valued audience must match. This option is mutually exclusive
      with Attesto core's `:trusted_audiences`; configuring both raises. The
      `:resource` form requires a pinned `:base_url` or `:origin`.

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
  alias AttestoMCP.Auth
  alias AttestoMCP.Plug.Authenticate
  alias AttestoMCP.Plug.RequireScopes

  require Logger

  @boundary_private_key :attesto_mcp_protect_resource_boundary

  @typedoc "An opaque, prepared protected-resource boundary."
  @opaque protection :: %{
            required(:authenticate) => keyword(),
            required(:boundary_id) => binary(),
            required(:require_scopes) => nil,
            required(:scope_opts) => keyword()
          }

  # Options that RequireScopes consumes. The scope set is its own; the rest are
  # shared with Authenticate so both steps render through one error envelope and
  # read the same assigns.
  @scope_keys [:scope, :scopes]
  @shared_keys [
    :send_error,
    :www_authenticate,
    :no_store,
    :resource_metadata,
    :allow_http,
    :claims_key,
    :scopes_key
  ]

  @impl Plug
  def init(opts) when is_list(opts) do
    protection = build_protection(opts)

    Map.put(
      protection,
      :require_scopes,
      RequireScopes.init(Keyword.merge(protection.scope_opts, Keyword.take(opts, @scope_keys)))
    )
  end

  @impl Plug
  def call(_conn, %{require_scopes: nil}) do
    raise ArgumentError,
          "a split ProtectResource boundary must call authenticate/2 and authorize/3 explicitly"
  end

  def call(conn, %{require_scopes: require_scopes} = protection) do
    conn = authenticate(conn, protection)

    if conn.halted do
      conn
    else
      RequireScopes.call(conn, require_scopes)
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
    authenticate = Authenticate.init(authenticate_opts(opts))

    %{
      authenticate: authenticate,
      require_scopes: nil,
      scope_opts: Keyword.take(authenticate, @shared_keys)
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
      |> Authenticate.oauth_error_opts()

    OAuthError.unauthorized(
      conn,
      Auth.scheme(conn.assigns[claims_key]),
      "invalid_token",
      Keyword.put(transport, :description, "request was not authenticated by this protected-resource boundary")
    )
  end

  defp rename_resource(opts) do
    case {Keyword.fetch(opts, :resource), Keyword.fetch(opts, :resource_path)} do
      {{:ok, _resource}, {:ok, _resource_path}} ->
        raise ArgumentError,
              "use :resource_path for an endpoint path; do not configure both :resource and :resource_path"

      {{:ok, resource}, :error} ->
        warn_deprecated_resource_alias_once()

        opts
        |> Keyword.delete(:resource)
        |> Keyword.put(:resource_path, resource)

      {:error, _resource_path} ->
        opts
    end
  end

  defp warn_deprecated_resource_alias_once do
    key = {__MODULE__, :resource_alias_warning_emitted}

    if !:persistent_term.get(key, false) do
      :persistent_term.put(key, true)

      Logger.warning(
        "AttestoMCP.Plug.ProtectResource :resource is deprecated because Metadata uses it for an absolute URI; " <>
          "use :resource_path for the endpoint path"
      )
    end
  end
end
