defmodule AttestoMCP.Plug.Authenticate do
  @moduledoc """
  Authenticate a protected MCP endpoint with Attesto.

  This plug delegates token, DPoP, and mTLS verification to
  `Attesto.Plug.Authenticate`, then assigns MCP-friendly auth context for the
  host server.

  Defaults:

    * `:claims_key` - `:attesto_mcp_claims`
    * `:scopes_key` - `:attesto_mcp_scopes`
    * `:sender_key` - `:attesto_mcp_sender`
    * `:principal_key` - `:attesto_mcp_principal`
    * `:context_key` - `:attesto_context`

  Alongside the MCP-specific assigns above, the plug also assigns a single
  protocol-shaped context map under `:context_key` (default `:attesto_context`),
  identical in shape to the one `AttestoPhoenix.Plug.Authenticate` assigns:
  `%{subject, client_id, scope (list), claims, cnf, principal}`. This is the
  canonical cross-plug auth context; `AttestoMCP.Anubis.put_auth/1` projects it
  into the Anubis frame regardless of which authenticator ran.

  Options accepted by `Attesto.Plug.Authenticate`, including `:config`,
  `:replay_check`, `:nonce_check`, `:nonce_issue`, `:cert_der`,
  `:trusted_audiences`, `:htu`, `:credential_from_conn`, `:bearer_methods`,
  `:send_error`, `:www_authenticate`, and `:no_store`, are passed through.
  `:origin` is this plug's own option (see below) and is not passed to core
  as core's `:origin`; a pinned origin reaches core as the DPoP `:htu`.

  An explicit audience policy is required at initialization: configure
  `:resource_audience` or `:trusted_audiences`. Publishing RFC 9728 metadata,
  pinning an origin, or setting `config.audience` alone does not select this
  policy. Neither `nil` nor `false` is an audience decision. Prefer
  `resource_audience: :resource` with a pinned origin and resource path.

  MCP defaults to `bearer_methods: [:header]`, matching protected-resource
  metadata that advertises `bearer_methods_supported: ["header"]`. A host that
  genuinely needs RFC 6750 §2.2 form-body tokens can opt in with
  `bearer_methods: [:header, :body]`, but body credentials are easier to leak
  through logs, caches, retries, and replay tooling than an `Authorization`
  header.

  Every call is wrapped in the `[:attesto_mcp, :authenticate]` telemetry
  span described in `AttestoMCP.Telemetry`, whose `:stop` event names the
  outcome, and the outcome is recorded on the connection for
  `AttestoMCP.Telemetry.outcome/1`. The `:send_error` hook a host supplies
  still renders every refusal; it is called through that recording step.

  Additional options:

    * `:resource_audience` - confines the token to this protected resource.
      Use `:resource` to derive the identifier from `:resource_path`, or pass a
      literal identifier / `(conn -> identifier)` / MFA callback. The resolved
      identifier becomes Attesto core's complete `:trusted_audiences` list, so
      a scalar `aud` must equal it and every member of an array-valued `aud`
      must equal it. `:resource_audience` and `:trusted_audiences` are mutually
      exclusive; configuring both raises rather than silently weakening either
      policy. A callback must return a valid identifier; `nil` or another
      malformed result fails authentication and never disables confinement.
      The `:resource` form requires a valid pinned `:base_url` or `:origin` at
      initialization so the request `Host` cannot choose the audience.
    * `:trusted_audiences` - deliberate alternative to `:resource_audience`:
      a non-empty list of non-empty audience identifiers, or a one-arity
      resolver returning that list. This replaces `config.audience`; every
      member of a token's audience array must be trusted. The resolver follows
      `Attesto.Token.verify/3`'s contract: use verified claims to select trusted
      configuration, never trust `aud` itself or perform side effects. Invalid
      results fail authentication. Audience and origin callbacks must use
      trusted configuration, never an unchecked request `Host`.
    * `:principal` - optional callback (`(claims, sender -> ...)` or
      `{module, fun}` / `{module, fun, extra_args}`) that receives verified
      claims and sender context, returning `{:ok, principal}` or
      `{:error, reason}`. For `{module, fun, extra_args}` callbacks (`:principal`,
      `:resource_audience`, `:resource_metadata_url`), `AttestoMCP.Auth.invoke/2`
      **appends** `extra_args` after the per-call arguments
      (`apply(module, fun, call_args ++ extra_args)`).
    * `:resource_metadata_url` - URL string, `(conn -> url)` callback, or
      `{module, fun}` / `{module, fun, args}` tuple that appends an RFC 9728
      `resource_metadata` auth-param to `WWW-Authenticate` challenges unless a
      custom `:www_authenticate` callback is already supplied. This is a total
      override: it takes precedence over `:base_url`/`:origin`, and a `(conn ->
      url)` form that derives from the connection bypasses origin pinning - pin
      via `:base_url`/`:origin` (which the default derivation honors) rather than
      a conn-deriving `:resource_metadata_url` callback behind a proxy. A custom
      `:www_authenticate` callback replaces challenge handling entirely, so it
      must append its own `resource_metadata` if wanted. Literal URLs are
      validated at initialization. Invalid callback results are omitted and
      logged once without including the invalid value.
    * `:resource_path` - MCP endpoint path used to derive
      `:resource_metadata_url`. Its origin is resolved by
      `AttestoMCP.Metadata.resolve_origin/2`, so a pinned origin applies.
    * `:base_url` / `:origin` - the external origin clients address this
      resource by (a `String.t()`, a `(conn -> url)` callback, or a
      `{module, fun}` / `{module, fun, args}` tuple). It pins the origin of the
      derived `resource_metadata` challenge URL, the `resource_audience:
      :resource` identifier, and the DPoP target URI (see below), instead of
      deriving them from the request connection. Use it behind a
      TLS-terminating proxy and on any server that answers more than one
      `Host`. When omitted, the live request origin is used only for discovery
      and Bearer-only mounts. This origin is the resource server's own; it is
      independent of the `:config` issuer (the authorization server). Mandatory
      when `resource_audience: :resource` is enabled, and one of `:base_url`,
      `:origin`, `:htu`, or `allow_dynamic_origin: true` with `:allowed_hosts`
      is required when the mount accepts DPoP.
    * `:allow_dynamic_origin` - set `true` (only alongside `:allowed_hosts`)
      to permit deriving the DPoP target URI from the request `Host` when the
      host matches the explicit `:allowed_hosts` allowlist. Mutually exclusive
      with `:base_url` and `:origin`. Intended for explicitly local multi-host
      development endpoints.
    * `:allowed_hosts` - non-empty list of host or `host:port` strings allowed
      when `allow_dynamic_origin: true` is configured. Requests for any other
      `Host` are refused with HTTP 401 (`invalid_token`).
    * `:allow_http` - permit an HTTP `resource_metadata` URL only for a loopback
      development endpoint. HTTPS remains the default.

  ## DPoP target URI

  RFC 9449 §4.3 binds a DPoP proof to the URI of the request it was made for
  (`htu`), so a proof sent to one server cannot be replayed to another. The URI
  a proof must sign is chosen in this order:

    1. an explicit `:htu` callback (`(conn -> uri)`), passed to
       `Attesto.Plug.Authenticate` unchanged;
    2. with `:base_url` or `:origin` pinned, the resolved origin followed by
       `conn.request_path` (`dpop_target_uri/2`). The request's scheme, `Host`
       header, and port are not used. A pinned value with a path prefix
       (`"https://example.com/tools"`) assumes the proxy strips that prefix,
       so the application sees `/mcp` for an external `/tools/mcp`;
    3. with `allow_dynamic_origin: true` and `:allowed_hosts`, requests whose
       `Host` is in `:allowed_hosts` use the request's origin followed by
       `conn.request_path`, and requests for any other `Host` are refused.

  A mount that accepts DPoP (`:replay_check` or
  `dpop_replay_unprotected_acknowledged?: true`) refuses to initialize unless
  one of `:base_url`, `:origin`, `:htu`, or `allow_dynamic_origin: true` with
  `:allowed_hosts` is configured. Malformed `:htu` values raise `ArgumentError`
  at initialization instead of discarding the origin pin. Bearer-only mounts
  are unaffected.

  Pin `:base_url` (or `:origin`) on every endpoint that accepts DPoP-bound
  tokens:

      plug AttestoMCP.Plug.ProtectResource,
        config: &MyApp.Attesto.config/0,
        replay_check: &MyApp.DPoPReplay.check_and_record/2,
        resource_path: "/mcp",
        resource_audience: :resource,
        scopes: [AttestoMCP.Scopes.tools_call()],
        base_url: "https://mcp.example.com"

  Use `:htu` instead when one endpoint answers on several origins, or when a
  proxy rewrites the path in a way a prefix does not describe. Build it from
  configured origins, not from request headers.
  """

  @behaviour Plug

  alias Attesto.Plug.ResourceAuthenticate
  alias AttestoMCP.Telemetry

  @impl Plug
  def init(opts) do
    host = Keyword.get(opts, :send_error)

    AttestoMCP.Auth.with_resource_errors(fn ->
      opts
      |> Keyword.put_new(:claims_key, :attesto_mcp_claims)
      |> Keyword.put_new(:scopes_key, :attesto_mcp_scopes)
      |> Keyword.put_new(:sender_key, :attesto_mcp_sender)
      |> Keyword.put_new(:principal_key, :attesto_mcp_principal)
      |> Keyword.put_new(:bearer_methods, [:header])
      |> Keyword.put(:policy_rejection_send_error, {Telemetry, :send_error, [host, :policy_rejected]})
      |> Telemetry.wrap_send_error()
      |> ResourceAuthenticate.init()
    end)
  end

  @impl Plug
  def call(conn, opts) do
    Telemetry.span(:authenticate, fn ->
      conn = conn |> Telemetry.put_outcome(nil) |> ResourceAuthenticate.call(opts)
      conn = if conn.halted, do: conn, else: Telemetry.put_outcome(conn, :ok)
      {conn, Telemetry.stop_metadata(conn, Keyword.get(opts, :sender_key, :attesto_mcp_sender))}
    end)
  end

  @doc false
  defdelegate host_allowed?(conn, hosts), to: ResourceAuthenticate

  @doc """
  Returns the DPoP target URI (`htu`) a proof must sign for `conn` when the
  plug is configured with `opts` and no `:htu`: the origin resolved by
  `AttestoMCP.Metadata.resolve_origin/2` followed by `conn.request_path`.

  With a pinned `:base_url` or `:origin`, the request's scheme, `Host` header,
  and port do not affect the result. A pinned value carrying a path prefix is
  joined with `conn.request_path`, which matches a proxy that strips that
  prefix before the request reaches the application. Without a pin, the
  resolved origin is the request's own.

      iex> conn = Plug.Test.conn(:post, "http://10.0.0.5:4000/mcp")
      iex> AttestoMCP.Plug.Authenticate.dpop_target_uri(conn, base_url: "https://mcp.example.com")
      "https://mcp.example.com/mcp"
  """
  defdelegate dpop_target_uri(conn, opts), to: ResourceAuthenticate

  @doc false
  defdelegate oauth_error_opts(opts), to: ResourceAuthenticate

  @doc false
  defdelegate oauth_error_metadata_opts(opts), to: ResourceAuthenticate

  @doc false
  defdelegate resolve_resource_metadata_url(conn, callback, fallback), to: ResourceAuthenticate

  @doc false
  defdelegate resolve_resource_metadata_url(conn, callback, fallback, allow_http?), to: ResourceAuthenticate

  @doc false
  defdelegate resolve_validated_resource_metadata_url(conn, resolver, allow_http?), to: ResourceAuthenticate

  @doc false
  @deprecated "Pass :resource_metadata to Attesto.Plug.OAuthError"
  defdelegate metadata_www_authenticate(opts), to: ResourceAuthenticate
end
