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
        resource_audience: :resource,
        scopes: [AttestoMCP.Scopes.tools_call()],
        base_url: "https://mcp.example.com"

  `init/1` returns no closures, so the plug works as a compile-time router
  pipeline plug (`plug_init_mode: :compile`, the production default). As Plug
  requires under `:compile` mode, any callback the host passes (`:config`,
  `:replay_check`, `:send_error`, …) must be a remote capture (`&Mod.fun/n`) or
  an MFA tuple (`{Mod, :fun}`), not an anonymous `fn`.

  This is exactly equivalent to:

      plug AttestoMCP.Plug.Authenticate,
        config: &MyApp.Attesto.config/0,
        replay_check: &MyApp.DPoPReplay.check_and_record/2,
        resource_path: "/mcp",
        resource_audience: :resource,
        base_url: "https://mcp.example.com"

      plug AttestoMCP.Plug.RequireScopes,
        scopes: [AttestoMCP.Scopes.tools_call()]

  ## Dynamically classified requests

  Some protected resources cannot know the required scope until a bounded
  request envelope has been classified. For that case, use the explicit
  two-phase API:

      protection =
        AttestoMCP.Plug.ProtectResource.prepare(
          config: &MyApp.Attesto.config/0,
          resource_path: "/mcp",
          base_url: "https://mcp.example.com",
          resource_audience: :resource
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

  Both `init/1` and `prepare/1` require an explicit `:resource_audience` or
  `:trusted_audiences` policy and raise `ArgumentError` without one. Metadata,
  an origin pin, and `config.audience` alone do not select an audience policy.
  A `nil` or `false` `:resource_audience` still requires `:trusted_audiences`.

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
    * `:base_url` (or `:origin`) - the external origin clients address this
      resource by (a `String.t()` or `(conn -> url)`), instead of trusting the
      request authority. It pins the `resource_metadata` challenge URL, the
      `resource_audience: :resource` identifier, and the DPoP target URI
      (`htu`) a proof must sign: the pinned origin followed by
      `conn.request_path`, unless an explicit `:htu` is given. Set it on every
      endpoint that accepts DPoP-bound tokens unless an explicit `:htu` or
      allowlisted dynamic origin is configured; otherwise initialization fails. It is required with `resource_audience:
      :resource`. Invalid literals fail at initialization and invalid callback
      results fail at request time. See "DPoP target URI" in
      `AttestoMCP.Plug.Authenticate` and `guides/proxy_origin.md`.
    * `:allow_http` - permit an HTTP `resource_metadata` URL only for a loopback
      development endpoint. HTTPS remains the default.
    * `:resource_audience` - confines access tokens to this protected resource;
      `:resource` derives its audience identifier from the resource path and
      resolved origin. A scalar token audience must match, and every member of
      an array-valued audience must match. This option is mutually exclusive
      with Attesto core's `:trusted_audiences`; configuring both raises. The
      `:resource` form requires a pinned `:base_url` or `:origin`.
    * `:trusted_audiences` - deliberate alternative policy: a non-empty list of
      non-empty identifiers or a one-arity claims resolver returning that list.
      See `AttestoMCP.Plug.Authenticate` for the resolver's trust contract.

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

  alias Attesto.Plug.ProtectResource
  alias AttestoMCP.Plug.Authenticate
  alias AttestoMCP.Plug.RequireScopes

  require Logger

  @opaque protection :: map()
  @adapters [authenticate: Authenticate, require_scopes: RequireScopes]

  @impl Plug
  def init(opts), do: ProtectResource.init(rename_resource(opts), @adapters)

  @impl Plug
  defdelegate call(conn, protection), to: ProtectResource

  @doc "Prepare a dynamically classified MCP resource boundary."
  def prepare(opts), do: ProtectResource.prepare(rename_resource(opts), @adapters)

  @doc "Authenticate through the prepared boundary."
  defdelegate authenticate(conn, protection), to: ProtectResource

  @doc "Authorize the operation scopes through the same boundary."
  def authorize(conn, protection, scopes) do
    if is_list(scopes),
      do: AttestoMCP.Scopes.reject_offline_access!(scopes, "AttestoMCP.Plug.ProtectResource")

    ProtectResource.authorize(conn, protection, scopes)
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
