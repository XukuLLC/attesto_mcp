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

  MCP defaults to `bearer_methods: [:header]`, matching protected-resource
  metadata that advertises `bearer_methods_supported: ["header"]`. A host that
  genuinely needs RFC 6750 §2.2 form-body tokens can opt in with
  `bearer_methods: [:header, :body]`, but body credentials are easier to leak
  through logs, caches, retries, and replay tooling than an `Authorization`
  header.

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
    * `:principal` - optional callback that receives verified claims and sender
      context, returning `{:ok, principal}` or `{:error, reason}`.
    * `:resource_metadata_url` - URL string, `(conn -> url)` callback, or
      `{module, fun}` / `{module, fun, args}` tuple that appends an RFC 9728
      `resource_metadata` auth-param to `WWW-Authenticate` challenges unless a
      custom `:www_authenticate` callback is already supplied. This is a total
      override: it takes precedence over `:base_url`/`:origin`, and a `(conn ->
      url)` form that derives from the connection bypasses origin pinning - pin
      via `:base_url`/`:origin` (which the default derivation honors) rather than
      a conn-deriving `:resource_metadata_url` callback behind a proxy. A custom
      `:www_authenticate` callback replaces challenge handling entirely, so it
      must append its own `resource_metadata` if wanted.
    * `:resource_path` - MCP endpoint path used to derive
      `:resource_metadata_url`. Its origin is resolved by
      `AttestoMCP.Metadata.resolve_origin/2`, so a pinned origin applies.
    * `:base_url` / `:origin` - pin the origin of the derived
      `resource_metadata` challenge URL (a `String.t()` or `(conn -> url)`),
      instead of deriving it from the request connection. Use behind a
      TLS-terminating proxy so the advertised metadata URL cannot be spoofed
      via `X-Forwarded-*`. When omitted, the live request origin is used. This
      origin is the resource server's own; it is independent of the `:config`
      issuer (the authorization server).
  """

  @behaviour Plug

  import Plug.Conn

  alias Attesto.Plug.Authenticate, as: AttestoAuthenticate
  alias Attesto.Plug.OAuthError
  alias AttestoMCP.Metadata

  @claims_key :attesto_mcp_claims
  @scopes_key :attesto_mcp_scopes
  @sender_key :attesto_mcp_sender
  @principal_key :attesto_mcp_principal
  @context_key :attesto_context

  @impl Plug
  def init(opts) when is_list(opts) do
    validate_audience_policy!(opts)
    AttestoAuthenticate.init(core_opts(opts, @claims_key))
    opts
  end

  @impl Plug
  def call(conn, opts) do
    claims_key = Keyword.get(opts, :claims_key, @claims_key)

    conn =
      conn
      |> AttestoAuthenticate.call(
        core_opts(opts, claims_key)
        |> resolve_config_callback()
        |> put_resource_audience(conn, opts)
      )

    if conn.halted do
      conn
    else
      assign_context(conn, opts, claims_key)
    end
  end

  # RFC 8707 / RFC 9728: enforce that the access token is audienced to THIS
  # protected resource. When `:resource_audience` is set, the token's `aud` is
  # checked through Attesto's strict `:trusted_audiences` policy against this
  # resource's identifier (the same value advertised as the RFC 9728 metadata
  # `resource`). This rejects both a sibling scalar audience and an array that
  # mixes this resource with any other audience. The identifier is computed per
  # request because it honors the live / pinned origin; absent, the host config
  # audience (or an explicitly supplied core policy) is used unchanged.
  defp put_resource_audience(core, conn, opts) do
    validate_audience_policy!(opts)

    case Keyword.get(opts, :resource_audience) do
      nil -> core
      false -> core
      policy -> Keyword.put(core, :trusted_audiences, [resolve_resource_audience(policy, conn, opts)])
    end
  end

  defp validate_audience_policy!(opts) do
    resource_audience = Keyword.get(opts, :resource_audience)

    if resource_audience not in [nil, false] and Keyword.has_key?(opts, :trusted_audiences) do
      raise ArgumentError,
            ":resource_audience and :trusted_audiences are mutually exclusive; choose one audience policy"
    end

    if resource_audience == :resource and not is_binary(Keyword.get(opts, :resource_path)) do
      raise ArgumentError,
            "resource_audience: :resource requires a :resource / :resource_path option to derive the audience"
    end

    if !valid_resource_audience_policy?(resource_audience) do
      raise ArgumentError,
            ":resource_audience must be :resource, a non-empty identifier, a one-arity function, or an MFA tuple"
    end

    :ok
  end

  defp valid_resource_audience_policy?(value) when value in [nil, false, :resource], do: true
  defp valid_resource_audience_policy?(value) when is_binary(value), do: value != ""
  defp valid_resource_audience_policy?(value) when is_function(value, 1), do: true

  defp valid_resource_audience_policy?({module, fun}) when is_atom(module) and is_atom(fun), do: true

  defp valid_resource_audience_policy?({module, fun, args}) when is_atom(module) and is_atom(fun) and is_list(args),
    do: true

  defp valid_resource_audience_policy?(_value), do: false

  # `:resource` derives the identifier from the configured `:resource_path` and
  # resolved origin. Other supported values are literal identifiers or
  # `(conn -> identifier)` callbacks in function / MFA form. A callback result
  # is deliberately not treated as an enable/disable signal: malformed values
  # become a malformed one-item core trust list and fail token verification.
  defp resolve_resource_audience(:resource, conn, opts), do: resource_audience_from_path(conn, opts)
  defp resolve_resource_audience(value, conn, _opts), do: invoke_resource_audience(value, conn)

  defp invoke_resource_audience(value, _conn) when is_binary(value), do: value
  defp invoke_resource_audience(fun, conn) when is_function(fun, 1), do: fun.(conn)

  defp invoke_resource_audience({m, f}, conn) when is_atom(m) and is_atom(f), do: apply(m, f, [conn])

  defp invoke_resource_audience({m, f, a}, conn) when is_atom(m) and is_atom(f) and is_list(a),
    do: apply(m, f, [conn | a])

  defp resource_audience_from_path(conn, opts) do
    case Keyword.get(opts, :resource_path) do
      path when is_binary(path) ->
        Metadata.resource_identifier(conn, path, opts)

      _ ->
        # Fail closed: the host asked to confine the token to THIS resource's
        # audience but supplied no resource path to derive it from. Silently
        # falling back to the global `config.audience` would disable the
        # confinement the host explicitly requested.
        raise ArgumentError,
              "resource_audience: :resource requires a :resource / :resource_path option to derive the audience"
    end
  end

  # Attesto core resolves a zero-arity function itself, while this wrapper has
  # historically also accepted MFA config callbacks. Normalize every supported
  # callback form before handing the options to core so enabling route audience
  # confinement cannot change whether a host's config callback works.
  defp resolve_config_callback(core) do
    config =
      case Keyword.fetch!(core, :config) do
        fun when is_function(fun, 0) -> fun.()
        {module, fun} when is_atom(module) and is_atom(fun) -> apply(module, fun, [])
        {module, fun, args} when is_atom(module) and is_atom(fun) and is_list(args) -> apply(module, fun, args)
        config -> config
      end

    Keyword.put(core, :config, config)
  end

  defp assign_context(conn, opts, claims_key) do
    claims = conn.assigns[claims_key]
    sender = sender_context(claims)
    scopes = scopes(claims)

    # Resolve the optional principal BEFORE assigning, so a principal-callback
    # rejection halts without leaving partial context on the conn.
    case resolve_principal(opts, claims, sender) do
      {:ok, principal} ->
        conn
        |> assign(Keyword.get(opts, :scopes_key, @scopes_key), scopes)
        |> assign(Keyword.get(opts, :sender_key, @sender_key), sender)
        |> maybe_assign_principal(opts, principal)
        |> assign(Keyword.get(opts, :context_key, @context_key), context(claims, scopes, principal))

      :error ->
        OAuthError.unauthorized(conn, scheme_of(claims), "invalid_token", error_opts(opts, []))
    end
  end

  defp resolve_principal(opts, claims, sender) do
    case Keyword.get(opts, :principal) do
      nil ->
        {:ok, nil}

      callback ->
        case invoke(callback, [claims, sender]) do
          {:ok, principal} -> {:ok, principal}
          {:error, _reason} -> :error
        end
    end
  end

  defp maybe_assign_principal(conn, _opts, nil), do: conn

  defp maybe_assign_principal(conn, opts, principal),
    do: assign(conn, Keyword.get(opts, :principal_key, @principal_key), principal)

  # The canonical cross-plug auth context, shaped identically to
  # `AttestoPhoenix.Plug.Authenticate`'s `:attesto_context` so a single
  # downstream consumer (e.g. `AttestoMCP.Anubis.put_auth/1`) reads either.
  defp context(claims, scopes, principal) do
    %{
      subject: claims["sub"],
      client_id: claims["client_id"],
      scope: scopes,
      claims: claims,
      cnf: Map.get(claims, "cnf"),
      principal: principal
    }
  end

  @doc false
  # The `WWW-Authenticate` callback that appends the RFC 9728 `resource_metadata`
  # auth-param, shared so every rejection path the MCP plugs emit (token failure,
  # principal rejection, and - via `ProtectResource` - scope rejection) points a
  # client at the same metadata. Returns `nil` when the host supplied its own
  # `:www_authenticate` (a total override) or no metadata URL can be resolved.
  @spec metadata_www_authenticate(keyword()) :: (Plug.Conn.t(), String.t() -> Plug.Conn.t()) | nil
  def metadata_www_authenticate(opts) do
    cond do
      Keyword.has_key?(opts, :www_authenticate) ->
        nil

      metadata_url = metadata_url_resolver(opts) ->
        fn conn, challenge ->
          put_resp_header(conn, "www-authenticate", Metadata.append_resource_metadata(challenge, metadata_url.(conn)))
        end

      true ->
        nil
    end
  end

  defp core_opts(opts, claims_key) do
    opts
    |> Keyword.drop([
      :base_url,
      :context_key,
      :origin,
      :issuer,
      :principal,
      :principal_key,
      :resource_metadata_url,
      :resource_path,
      :resource_audience,
      :scopes_key,
      :sender_key
    ])
    |> Keyword.put_new(:bearer_methods, [:header])
    |> Keyword.put(:claims_key, claims_key)
    |> maybe_put_metadata_challenge(opts)
  end

  defp maybe_put_metadata_challenge(core_opts, opts) do
    case metadata_www_authenticate(opts) do
      nil -> core_opts
      www_authenticate -> Keyword.put_new(core_opts, :www_authenticate, www_authenticate)
    end
  end

  defp metadata_url_resolver(opts) do
    case Keyword.get(opts, :resource_metadata_url) do
      url when is_binary(url) ->
        fn _conn -> url end

      fun when is_function(fun, 1) ->
        fun

      {module, fun} when is_atom(module) and is_atom(fun) ->
        fn conn -> apply(module, fun, [conn]) end

      {module, fun, args} when is_atom(module) and is_atom(fun) and is_list(args) ->
        fn conn -> apply(module, fun, [conn | args]) end

      _ ->
        metadata_url_from_resource_path(Keyword.get(opts, :resource_path), opts)
    end
  end

  # The challenge URL must agree with the served metadata `resource`, so resolve
  # its origin the same way `AttestoMCP.Metadata` does: a pinned `:base_url` /
  # `:origin` wins over the request connection. (The issuer is not used here -
  # it is the authorization server, not the resource origin.)
  defp metadata_url_from_resource_path(path, opts) when is_binary(path) do
    fn conn -> Metadata.protected_resource_url(conn, path, opts) end
  end

  defp metadata_url_from_resource_path(_path, _opts), do: nil

  defp scopes(%{"scope" => scope}) when is_binary(scope), do: String.split(scope, ~r/\s+/, trim: true)
  defp scopes(_claims), do: []

  defp sender_context(%{"cnf" => %{"jkt" => jkt}}) when is_binary(jkt) do
    %{binding: :dpop, jkt: jkt}
  end

  defp sender_context(%{"cnf" => %{"x5t#S256" => thumbprint}}) when is_binary(thumbprint) do
    %{binding: :mtls, x5t_s256: thumbprint}
  end

  defp sender_context(_claims), do: %{binding: :bearer}

  defp scheme_of(%{"cnf" => %{"jkt" => jkt}}) when is_binary(jkt), do: :dpop
  defp scheme_of(_claims), do: :bearer

  defp error_opts(opts, extra) do
    opts
    |> Keyword.take([:send_error, :www_authenticate, :no_store])
    |> put_metadata_challenge(opts)
    |> Keyword.merge(extra)
  end

  # So a principal-callback rejection (a 401 emitted here, after token
  # verification succeeded) carries the same `resource_metadata` pointer as the
  # token-failure path, rather than a bare challenge.
  defp put_metadata_challenge(taken, opts) do
    case metadata_www_authenticate(opts) do
      nil -> taken
      www_authenticate -> Keyword.put_new(taken, :www_authenticate, www_authenticate)
    end
  end

  defp invoke(fun, args) when is_function(fun), do: apply(fun, args)

  defp invoke({module, fun}, args) when is_atom(module) and is_atom(fun), do: apply(module, fun, args)

  defp invoke({module, fun, extra}, args) when is_atom(module) and is_atom(fun) and is_list(extra),
    do: apply(module, fun, args ++ extra)
end
