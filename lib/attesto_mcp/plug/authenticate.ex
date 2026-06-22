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
  `:replay_check`, `:nonce_check`, `:nonce_issue`, `:cert_der`, `:htu`,
  `:credential_from_conn`, `:bearer_methods`, `:send_error`,
  `:www_authenticate`, and `:no_store`, are passed through.

  MCP defaults to `bearer_methods: [:header]`, matching protected-resource
  metadata that advertises `bearer_methods_supported: ["header"]`. A host that
  genuinely needs RFC 6750 §2.2 form-body tokens can opt in with
  `bearer_methods: [:header, :body]`, but body credentials are easier to leak
  through logs, caches, retries, and replay tooling than an `Authorization`
  header.

  Additional options:

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

  alias Attesto.Config
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
    AttestoAuthenticate.init(core_opts(opts, @claims_key))
    opts
  end

  @impl Plug
  def call(conn, opts) do
    claims_key = Keyword.get(opts, :claims_key, @claims_key)

    conn =
      conn
      |> AttestoAuthenticate.call(core_opts(opts, claims_key) |> override_resource_audience(conn, opts))

    if conn.halted do
      conn
    else
      assign_context(conn, opts, claims_key)
    end
  end

  # RFC 8707 / RFC 9728: enforce that the access token is audienced to THIS
  # protected resource. When `:resource_audience` is set, the token's `aud` is
  # validated against this resource's identifier (the same value advertised as
  # the RFC 9728 metadata `resource`) rather than the host's global
  # `config.audience` - so a token minted for a sibling resource is rejected here
  # (audience confinement, RFC 8707 §1). Computed per request because the
  # resource identifier honors the live / pinned origin; absent, the host config
  # audience is used unchanged (backward compatible).
  defp override_resource_audience(core, conn, opts) do
    case resource_audience(conn, opts) do
      nil -> core
      audience -> Keyword.put(core, :config, %{resolve_config(core) | audience: audience})
    end
  end

  defp resource_audience(conn, opts) do
    case Keyword.get(opts, :resource_audience) do
      nil -> nil
      false -> nil
      # `:resource` derives the identifier from the configured `:resource_path`
      # and the resolved origin - the canonical metadata `resource` value.
      :resource -> resource_audience_from_path(conn, opts)
      value when is_binary(value) -> value
      fun when is_function(fun, 1) -> fun.(conn)
      {m, f} when is_atom(m) and is_atom(f) -> apply(m, f, [conn])
      {m, f, a} when is_atom(m) and is_atom(f) and is_list(a) -> apply(m, f, [conn | a])
    end
  end

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

  defp resolve_config(core) do
    case Keyword.fetch!(core, :config) do
      %Config{} = config -> config
      fun when is_function(fun, 0) -> fun.()
      {m, f} when is_atom(m) and is_atom(f) -> apply(m, f, [])
      {m, f, a} when is_atom(m) and is_atom(f) and is_list(a) -> apply(m, f, a)
    end
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
