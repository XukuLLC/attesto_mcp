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
      must append its own `resource_metadata` if wanted. Literal URLs are
      validated at initialization. Invalid callback results are omitted and
      logged once without including the invalid value.
    * `:resource_path` - MCP endpoint path used to derive
      `:resource_metadata_url`. Its origin is resolved by
      `AttestoMCP.Metadata.resolve_origin/2`, so a pinned origin applies.
    * `:base_url` / `:origin` - pin the origin of the derived
      `resource_metadata` challenge URL (a `String.t()` or `(conn -> url)`),
      instead of deriving it from the request connection. Use behind a
      TLS-terminating proxy so the advertised metadata URL cannot be spoofed
      via `X-Forwarded-*`. When omitted, the live request origin is used. This
      origin is the resource server's own; it is independent of the `:config`
      issuer (the authorization server). The option is mandatory when
      `resource_audience: :resource` is enabled.
    * `:allow_http` - permit an HTTP `resource_metadata` URL for a deliberate
      development endpoint. HTTPS remains the default.
  """

  @behaviour Plug

  import Plug.Conn

  alias Attesto.Plug.Authenticate, as: AttestoAuthenticate
  alias Attesto.Plug.OAuthError
  alias Attesto.URI, as: AttestoURI
  alias AttestoMCP.Auth
  alias AttestoMCP.Metadata
  alias AttestoMCP.Telemetry

  require Logger

  @claims_key :attesto_mcp_claims
  @scopes_key :attesto_mcp_scopes
  @sender_key :attesto_mcp_sender
  @principal_key :attesto_mcp_principal
  @context_key :attesto_context
  @mcp_option_keys [
    :base_url,
    :context_key,
    :origin,
    :principal,
    :principal_key,
    :resource_audience,
    :resource_path,
    :scopes_key,
    :sender_key
  ]

  @impl Plug
  def init(opts) when is_list(opts) do
    Metadata.validate_origin_options!(opts)
    validate_resource_path!(opts)
    validate_audience_policy!(opts)
    validate_resource_metadata_url!(opts)

    normalized_core_opts =
      opts
      |> core_opts(Keyword.get(opts, :claims_key, @claims_key))
      |> AttestoAuthenticate.init()

    # Retain MCP-only configuration while preserving every validation and
    # normalization performed by the core plug at pipeline initialization.
    Keyword.merge(normalized_core_opts, Keyword.take(opts, @mcp_option_keys))
  end

  @impl Plug
  def call(conn, opts) do
    claims_key = Keyword.get(opts, :claims_key, @claims_key)
    sender_key = Keyword.get(opts, :sender_key, @sender_key)

    Telemetry.span(:authenticate, fn ->
      conn =
        conn
        |> Telemetry.put_outcome(nil)
        |> AttestoAuthenticate.call(put_resource_audience(opts, conn, opts))

      conn = if conn.halted, do: conn, else: assign_context(conn, opts, claims_key)
      {conn, Telemetry.stop_metadata(conn, sender_key)}
    end)
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

    if resource_audience == :resource do
      Metadata.require_pinned_origin!(opts)
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

  defp validate_resource_path!(opts) do
    case Keyword.fetch(opts, :resource_path) do
      {:ok, resource_path} ->
        _ = Metadata.normalize_resource_path!(resource_path)
        :ok

      :error ->
        :ok
    end
  end

  # `:resource` derives the identifier from the configured `:resource_path` and
  # resolved origin. Other supported values are literal identifiers or
  # `(conn -> identifier)` callbacks in function / MFA form. A callback result
  # is deliberately not treated as an enable/disable signal: malformed values
  # become a malformed one-item core trust list and fail token verification.
  defp resolve_resource_audience(:resource, conn, opts) do
    Metadata.resource_identifier(conn, Keyword.fetch!(opts, :resource_path), opts)
  end

  defp resolve_resource_audience(value, conn, _opts), do: invoke_resource_audience(value, conn)

  defp invoke_resource_audience(value, _conn) when is_binary(value), do: value
  defp invoke_resource_audience(callback, conn), do: Auth.invoke(callback, [conn])

  defp assign_context(conn, opts, claims_key) do
    claims = conn.assigns[claims_key]
    sender = sender_context(claims)
    scopes = Auth.scopes(claims)

    # Resolve the optional principal before assigning the verified context.
    case resolve_principal(opts, claims, sender) do
      {:ok, principal} ->
        conn
        |> Telemetry.put_outcome(:ok)
        |> assign(Keyword.get(opts, :scopes_key, @scopes_key), scopes)
        |> assign(Keyword.get(opts, :sender_key, @sender_key), sender)
        |> assign(Keyword.get(opts, :principal_key, @principal_key), principal)
        |> assign(Keyword.get(opts, :context_key, @context_key), context(claims, scopes, principal))

      :error ->
        # The refusal is rendered as a generic invalid_token; the recording
        # hook is told the exact outcome because the envelope cannot show it.
        OAuthError.unauthorized(
          conn,
          Auth.scheme(claims),
          "invalid_token",
          error_opts(opts, send_error: policy_rejection_hook(opts))
        )
    end
  end

  defp resolve_principal(opts, claims, sender) do
    case Keyword.get(opts, :principal) do
      nil ->
        {:ok, nil}

      callback ->
        case Auth.invoke(callback, [claims, sender]) do
          {:ok, principal} -> {:ok, principal}
          _rejected -> :error
        end
    end
  end

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
  @spec oauth_error_opts(keyword()) :: keyword()
  def oauth_error_opts(opts),
    do: Keyword.take(opts, [:send_error, :www_authenticate, :no_store, :resource_metadata, :allow_http])

  @doc false
  @spec oauth_error_metadata_opts(keyword()) :: keyword()
  def oauth_error_metadata_opts(opts) do
    if Keyword.has_key?(opts, :www_authenticate) do
      []
    else
      []
      |> maybe_put_opt(:resource_metadata, metadata_url_resolver(opts))
      |> maybe_copy_opt(opts, :allow_http)
    end
  end

  @doc false
  @deprecated "Pass :resource_metadata to Attesto.Plug.OAuthError"
  @spec metadata_www_authenticate(keyword()) :: (Plug.Conn.t(), String.t() -> Plug.Conn.t()) | nil
  def metadata_www_authenticate(opts) do
    cond do
      Keyword.has_key?(opts, :www_authenticate) ->
        nil

      metadata_url = metadata_url_resolver(opts) ->
        fn conn, challenge ->
          rendered = render_metadata_challenge(challenge, resolve_metadata_url(metadata_url, conn), opts)
          put_resp_header(conn, "www-authenticate", rendered)
        end

      true ->
        nil
    end
  end

  defp render_metadata_challenge(challenge, url, opts) do
    if AttestoURI.https_identifier?(url, allow_http: Keyword.get(opts, :allow_http, false)) do
      append_resource_metadata = Function.capture(Metadata, :append_resource_metadata, 2)
      append_resource_metadata.(challenge, url)
    else
      challenge
    end
  end

  @doc false
  # Compatibility arity: this intentionally preserves the 2.0 callback/fallback
  # behavior and does not validate the returned URL. New internal integrations
  # use resolve_resource_metadata_url/4, which validates the selected URL.
  @spec resolve_resource_metadata_url(Plug.Conn.t(), term(), term()) :: term()
  def resolve_resource_metadata_url(conn, callback, fallback) do
    case resolve_metadata_url(callback, conn) do
      url when is_binary(url) and url != "" -> url
      _invalid -> resolve_metadata_url(fallback, conn)
    end
  end

  @doc false
  # Core invokes this MFA when a host callback has a derived-path fallback.
  # Invalid callback results are omitted, with a VM-wide warning emitted
  # once, instead of disappearing silently inside core's challenge renderer.
  @spec resolve_resource_metadata_url(Plug.Conn.t(), term(), term(), boolean()) :: term()
  def resolve_resource_metadata_url(conn, callback, fallback, allow_http?) do
    callback
    |> resolve_metadata_url(conn)
    |> valid_resource_metadata_url(allow_http?)
    |> case do
      {:ok, url} ->
        url

      :error ->
        warn_invalid_resource_metadata_once()
        resolve_validated_resource_metadata_url(conn, fallback, allow_http?)
    end
  end

  @doc false
  @spec resolve_validated_resource_metadata_url(Plug.Conn.t(), term(), boolean()) :: term()
  def resolve_validated_resource_metadata_url(conn, resolver, allow_http?) do
    resolver
    |> resolve_metadata_url(conn)
    |> valid_resource_metadata_url(allow_http?)
    |> case do
      {:ok, url} ->
        url

      :error ->
        warn_invalid_resource_metadata_once()
        nil
    end
  end

  defp policy_rejection_hook(opts) do
    case Keyword.get(opts, :send_error) do
      {Telemetry, :send_error, [host]} -> {Telemetry, :send_error, [host, :policy_rejected]}
      host -> {Telemetry, :send_error, [host, :policy_rejected]}
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
    |> put_oauth_error_metadata(opts)
    |> Telemetry.wrap_send_error()
  end

  defp put_oauth_error_metadata(core_opts, opts) do
    if Keyword.has_key?(opts, :www_authenticate) do
      Keyword.delete(core_opts, :resource_metadata)
    else
      core_opts
      |> maybe_put_opt(:resource_metadata, metadata_url_resolver(opts))
      |> maybe_copy_opt(opts, :allow_http)
    end
  end

  defp metadata_url_resolver(opts) do
    opts
    |> Keyword.get(:resource_metadata_url)
    |> metadata_url_resolver(opts)
  end

  defp metadata_url_resolver(url, _opts) when is_binary(url), do: url

  defp metadata_url_resolver(callback, opts)
       when is_function(callback, 1) or (is_tuple(callback) and tuple_size(callback) in [2, 3]),
       do: metadata_callback(callback, opts)

  defp metadata_url_resolver(nil, opts), do: validated_metadata_fallback(opts)
  defp metadata_url_resolver(_invalid, _opts), do: nil

  # The challenge URL must agree with the served metadata `resource`, so resolve
  # its origin the same way `AttestoMCP.Metadata` does: a pinned `:base_url` /
  # `:origin` wins over the request connection. (The issuer is not used here -
  # it is the authorization server, not the resource origin.)
  defp metadata_url_from_resource_path(path, opts) when is_binary(path) do
    origin_opts = Keyword.take(opts, [:base_url, :origin, :allow_http])
    {Metadata, :protected_resource_url, [path, origin_opts]}
  end

  defp metadata_url_from_resource_path(_path, _opts), do: nil

  defp metadata_callback(callback, opts) do
    fallback = metadata_url_from_resource_path(Keyword.get(opts, :resource_path), opts)
    allow_http? = Keyword.get(opts, :allow_http, false)

    if fallback,
      do: {__MODULE__, :resolve_resource_metadata_url, [callback, fallback, allow_http?]},
      else: {__MODULE__, :resolve_validated_resource_metadata_url, [callback, allow_http?]}
  end

  defp validated_metadata_fallback(opts) do
    case metadata_url_from_resource_path(Keyword.get(opts, :resource_path), opts) do
      nil ->
        nil

      fallback ->
        {__MODULE__, :resolve_validated_resource_metadata_url, [fallback, Keyword.get(opts, :allow_http, false)]}
    end
  end

  defp validate_resource_metadata_url!(opts) do
    case Keyword.fetch(opts, :resource_metadata_url) do
      :error ->
        :ok

      {:ok, spec} ->
        validate_resource_metadata_url_spec!(spec, opts)
    end
  end

  defp validate_resource_metadata_url_spec!(url, opts) when is_binary(url) do
    case valid_resource_metadata_url(url, Keyword.get(opts, :allow_http, false)) do
      {:ok, _url} -> :ok
      :error -> raise_invalid_resource_metadata_url!()
    end
  end

  defp validate_resource_metadata_url_spec!(fun, _opts) when is_function(fun, 1), do: :ok

  defp validate_resource_metadata_url_spec!({module, fun}, _opts) when is_atom(module) and is_atom(fun), do: :ok

  defp validate_resource_metadata_url_spec!({module, fun, args}, _opts)
       when is_atom(module) and is_atom(fun) and is_list(args), do: :ok

  defp validate_resource_metadata_url_spec!(_invalid, _opts), do: raise_invalid_resource_metadata_url!()

  defp valid_resource_metadata_url(url, allow_http?) do
    if AttestoURI.https_identifier?(url, allow_http: allow_http?), do: {:ok, url}, else: :error
  end

  defp raise_invalid_resource_metadata_url! do
    raise ArgumentError,
          ":resource_metadata_url must be an absolute HTTPS URL without userinfo or fragment; " <>
            "set allow_http: true only for a deliberate development endpoint"
  end

  defp warn_invalid_resource_metadata_once do
    key = {__MODULE__, :invalid_resource_metadata_warning_emitted}

    if !:persistent_term.get(key, false) do
      :persistent_term.put(key, true)

      Logger.warning(
        "AttestoMCP omitted an invalid resource_metadata callback result; " <>
          "return an absolute HTTPS URL or set allow_http: true for development"
      )
    end
  end

  defp resolve_metadata_url(url, _conn) when is_binary(url), do: url
  defp resolve_metadata_url(callback, conn), do: Auth.invoke(callback, [conn])

  defp sender_context(%{"cnf" => %{"jkt" => jkt}}) when is_binary(jkt) do
    %{binding: :dpop, jkt: jkt}
  end

  defp sender_context(%{"cnf" => %{"x5t#S256" => thumbprint}}) when is_binary(thumbprint) do
    %{binding: :mtls, x5t_s256: thumbprint}
  end

  defp sender_context(_claims), do: %{binding: :bearer}

  defp error_opts(opts, extra) do
    opts
    |> oauth_error_opts()
    |> Keyword.merge(extra)
  end

  defp maybe_put_opt(opts, _key, nil), do: opts
  defp maybe_put_opt(opts, key, value), do: Keyword.put(opts, key, value)

  defp maybe_copy_opt(target, source, key) do
    case Keyword.fetch(source, key) do
      {:ok, value} -> Keyword.put(target, key, value)
      :error -> target
    end
  end
end
