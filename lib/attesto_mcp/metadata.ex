defmodule AttestoMCP.Metadata do
  @moduledoc """
  Builders for OAuth metadata used by HTTP MCP authorization.

  MCP HTTP servers that require authorization act as OAuth protected resources.
  The MCP authorization spec points clients at RFC 9728 protected-resource
  metadata first, then at RFC 8414 authorization-server metadata. This module
  builds those documents without coupling the package to any MCP server SDK.

  ## Origin pinning behind a proxy

  The `resource` identifier and the default `authorization_servers` are origin
  values: a client reads them to learn where it is and where to get a token.
  By default they are derived from the live request connection
  (`conn.scheme`/`conn.host`/`conn.port`), which is correct for a simple
  single-host deployment.

  Behind a TLS-terminating reverse proxy that derivation is both fragile and a
  spoofing vector: `conn.scheme` is often `http`, `conn.host` is whatever
  `X-Forwarded-*` rewriting produced, and an attacker who can set
  `X-Forwarded-Host` could make the metadata advertise an attacker-controlled
  `resource` or authorization server. A FAPI-grade deployment should pin both
  instead of trusting the request:

    * The **`resource`** identifier and the well-known metadata URL use
      `resolve_origin/2` - the *resource server* origin, pinned via `:base_url`
      or `:origin` (a `String.t()`, a `(Plug.Conn.t() -> String.t())` callback,
      or a `{module, fun}` / `{module, fun, args}` tuple), falling back to the
      live request origin.
    * **`authorization_servers`** defaults to the `:config` issuer (or an
      explicit `:issuer` string) when one is supplied - the authorization server
      the host already trusts for token verification, advertised verbatim - and
      otherwise to the resource origin. The issuer is deliberately NOT used as
      the `resource` origin: RFC 9728 keeps the protected resource and its
      authorization server distinct, and in a FAPI deployment they are usually
      different hosts.

  Either can still be overridden outright with an explicit `:resource` /
  `:authorization_servers` opt. See `guides/proxy_origin.md` for the recipe.
  """

  alias Attesto.Config
  alias Attesto.Discovery
  alias Attesto.DPoP
  alias AttestoMCP.Scopes

  @protected_resource_fields ~w(
    authorization_details_types_supported
    bearer_methods_supported
    dpop_bound_access_tokens_required
    dpop_signing_alg_values_supported
    jwks_uri
    resource_documentation
    resource_name
    resource_policy_uri
    resource_signing_alg_values_supported
    resource_tos_uri
    scopes_supported
    signed_metadata
    tls_client_certificate_bound_access_tokens
  )a

  @doc """
  Build an RFC 9728 protected-resource metadata document.

  Required options:

    * `:resource` - the protected resource identifier, usually the canonical
      MCP server URI such as `"https://mcp.example.com/mcp"`.
    * `:authorization_servers` - a non-empty list of issuer identifiers.

  Common options include `:scopes_supported`, `:bearer_methods_supported`,
  `:dpop_signing_alg_values_supported`, and
  `:tls_client_certificate_bound_access_tokens`.
  """
  @spec protected_resource(keyword()) :: %{required(String.t()) => term()}
  def protected_resource(opts) when is_list(opts) do
    resource = Keyword.fetch!(opts, :resource)
    authorization_servers = Keyword.fetch!(opts, :authorization_servers)

    %{
      "authorization_servers" => authorization_servers,
      "resource" => resource
    }
    |> put_new(:bearer_methods_supported, ["header"])
    |> put_new(:dpop_signing_alg_values_supported, DPoP.allowed_algs())
    |> put_new(:scopes_supported, Scopes.all())
    |> merge_supported_fields(opts)
  end

  @doc """
  Build protected-resource metadata from a Plug connection and resource path.

  `resource_path` is the path of the MCP endpoint, for example `"/mcp"` or
  `"/mcp/admin"`. The `resource` identifier is `resolve_origin/2` (the resource
  server origin, pinned via `:base_url`/`:origin`) joined with that path.
  `:authorization_servers` defaults to the `:config` issuer (or an explicit
  `:issuer` string) when one is given - the trusted authorization server,
  advertised verbatim - and otherwise to the resource origin.

  An explicit `:resource` or `:authorization_servers` opt overrides the derived
  value, and short-circuits its derivation: a pinned origin / issuer callback is
  not invoked (and cannot fail) for a value the host supplied outright.
  """
  @spec protected_resource(Plug.Conn.t(), String.t(), keyword()) :: %{required(String.t()) => term()}
  def protected_resource(%Plug.Conn{} = conn, resource_path, opts \\ []) when is_binary(resource_path) do
    derive_resource? = not Keyword.has_key?(opts, :resource)
    derive_servers? = not Keyword.has_key?(opts, :authorization_servers)
    issuer = if derive_servers?, do: configured_issuer(opts)

    # Resolve the resource origin AT MOST ONCE, and only when a derived value
    # actually needs it: an explicit `:resource`/`:authorization_servers` never
    # triggers an origin/issuer callback, and `resource` + the `authorization_servers`
    # fallback share the same resolved origin (so a stateful callback cannot make
    # the document internally inconsistent).
    origin = if derive_resource? or (derive_servers? and is_nil(issuer)), do: resolve_origin(conn, opts)

    opts
    |> maybe_put(derive_resource?, :resource, fn -> origin <> normalize_path(resource_path) end)
    |> maybe_put(derive_servers?, :authorization_servers, fn -> if issuer, do: [issuer], else: [origin] end)
    |> Keyword.drop([:base_url, :origin, :issuer, :config])
    |> protected_resource()
  end

  @doc """
  Build the well-known metadata URL for an MCP resource path.

      iex> AttestoMCP.Metadata.protected_resource_url("https://mcp.example.com", "/mcp")
      "https://mcp.example.com/.well-known/oauth-protected-resource/mcp"

  A Plug connection can also be passed as the first argument.
  """
  @spec protected_resource_url(String.t(), String.t()) :: String.t()
  def protected_resource_url(base_url, resource_path) when is_binary(base_url) and is_binary(resource_path) do
    String.trim_trailing(base_url, "/") <> "/.well-known/oauth-protected-resource" <> normalize_path(resource_path)
  end

  @spec protected_resource_url(Plug.Conn.t(), String.t()) :: String.t()
  def protected_resource_url(%Plug.Conn{} = conn, resource_path) when is_binary(resource_path) do
    protected_resource_url(conn, resource_path, [])
  end

  @doc """
  Build the well-known metadata URL, resolving the origin via `resolve_origin/2`.

  Pass `:base_url`/`:origin` in `opts` to pin the resource origin (so the
  challenge URL matches a pinned `resource`); with no such opt the live request
  origin is used.
  """
  @spec protected_resource_url(Plug.Conn.t(), String.t(), keyword()) :: String.t()
  def protected_resource_url(%Plug.Conn{} = conn, resource_path, opts)
      when is_binary(resource_path) and is_list(opts) do
    conn
    |> resolve_origin(opts)
    |> protected_resource_url(resource_path)
  end

  @doc """
  Resolve the *resource server* origin used to build the `resource` identifier
  and the well-known metadata URL.

  This is the protected resource's own origin (RFC 9728 `resource`), which is
  distinct from the authorization server (`authorization_servers` / the
  `Attesto.Config` issuer) - the two are often different hosts in a FAPI
  deployment, so the issuer is NOT used here. Precedence:

    1. an explicit `:base_url` or `:origin` opt - a `String.t()`, a
       `(Plug.Conn.t() -> String.t())` callback, or a `{module, fun}` /
       `{module, fun, args}` tuple (the conn is prepended to `args`), resolved
       at request time;
    2. the live request origin (`conn.scheme`/`conn.host`/`conn.port`).

  A blank or non-binary pin is treated as "not configured" and falls back to the
  request origin; a trailing slash is trimmed so the result joins cleanly with a
  resource path.
  """
  @spec resolve_origin(Plug.Conn.t(), keyword()) :: String.t()
  def resolve_origin(%Plug.Conn{} = conn, opts) when is_list(opts) do
    pinned_origin(opts, conn) || base_url(conn)
  end

  @doc """
  The canonical RFC 8707 / RFC 9728 resource identifier for this protected
  resource: the resolved origin joined with the resource path (for example
  `"https://mcp.example.com/mcp"`).

  This is the SINGLE source for the value that must agree across the chain — the
  RFC 9728 metadata `resource` field, the RFC 8707 `resource` a client requests,
  the `aud` the authorization server mints, and the audience the resource-server
  plug validates. Driving the audience check and the advertised metadata from
  this one function is what makes them consistent by construction (a host cannot
  configure them into disagreement). Origin precedence is `resolve_origin/2`'s.
  """
  @spec resource_identifier(Plug.Conn.t(), String.t(), keyword()) :: String.t()
  def resource_identifier(%Plug.Conn{} = conn, resource_path, opts \\ []) when is_binary(resource_path) do
    resolve_origin(conn, opts) <> normalize_path(resource_path)
  end

  @doc """
  Build the `WWW-Authenticate` auth-param value for RFC 9728 metadata discovery.
  """
  @spec resource_metadata_param(String.t()) :: String.t()
  def resource_metadata_param(url) when is_binary(url), do: ~s(resource_metadata="#{escape(url)}")

  @doc """
  Append `resource_metadata` to a `WWW-Authenticate` challenge.
  """
  @spec append_resource_metadata(String.t(), String.t()) :: String.t()
  def append_resource_metadata(challenge, url) when is_binary(challenge) and is_binary(url) do
    challenge <> ", " <> resource_metadata_param(url)
  end

  @doc """
  Build the authorization-server metadata document by delegating to Attesto.
  """
  @spec authorization_server(Config.t(), keyword()) :: %{required(String.t()) => term()}
  def authorization_server(%Config{} = config, opts \\ []), do: Discovery.metadata(config, opts)

  defp merge_supported_fields(map, opts) do
    Enum.reduce(@protected_resource_fields, map, fn field, acc ->
      case Keyword.get(opts, field) do
        nil -> acc
        value -> Map.put(acc, Atom.to_string(field), value)
      end
    end)
  end

  defp put_new(map, key, value) do
    Map.put_new(map, Atom.to_string(key), value)
  end

  # Put a derived value only when the caller asked for derivation; the value
  # `fun` is invoked lazily, so an explicit `:resource` / `:authorization_servers`
  # short-circuits its (possibly callback-bearing, possibly failing) derivation.
  defp maybe_put(opts, false, _key, _fun), do: opts
  defp maybe_put(opts, true, key, fun), do: Keyword.put(opts, key, fun.())

  defp escape(value) do
    value
    |> String.replace("\\", "\\\\")
    |> String.replace("\"", "\\\"")
  end

  # The resource-server origin (RFC 9728 `resource`). A blank or non-binary
  # resolution is treated as "not configured" so a misconfigured pin fails back
  # to the request origin rather than producing relative/empty metadata. Trailing
  # slashes are trimmed because this value is joined with a resource path.
  defp pinned_origin(opts, conn) do
    # Resolve each key independently: a blank/non-binary `:base_url` yields to
    # `:origin` (rather than short-circuiting on `"" || ...`, where blank is
    # truthy), and a blank/non-binary `:origin` yields to the request origin.
    pinned(Keyword.get(opts, :base_url), conn) || pinned(Keyword.get(opts, :origin), conn)
  end

  defp pinned(spec, conn) do
    case invoke_origin(spec, conn) do
      url when is_binary(url) -> validate_origin(String.trim_trailing(url, "/"))
      _ -> nil
    end
  end

  # An origin pin must be an absolute `http(s)://host` base URL. Trim the trailing
  # slash first, then validate with URI.new/1 and require an http/https scheme and
  # a non-empty host, with no userinfo/query/fragment - so blank, relative, or
  # malformed pins ("", "/", "///", "/prefix", "mcp.example.com", "://x",
  # "https:///path", "https://u:p@h", "https://h?x=1", "https://h#f") are rejected
  # and yield to the next key / the request origin, rather than concatenating into
  # a relative, authority-less, or credential-leaking `resource` / well-known URL.
  # A port and a path prefix are allowed (the latter for path-prefix proxies).
  defp validate_origin(trimmed) do
    case URI.new(trimmed) do
      {:ok, %URI{scheme: scheme, host: host, userinfo: nil, query: nil, fragment: nil}}
      when scheme in ["http", "https"] and is_binary(host) and host != "" ->
        trimmed

      _ ->
        nil
    end
  end

  defp invoke_origin(url, _conn) when is_binary(url), do: url
  defp invoke_origin(fun, conn) when is_function(fun, 1), do: fun.(conn)

  defp invoke_origin({module, fun}, conn) when is_atom(module) and is_atom(fun), do: apply(module, fun, [conn])

  defp invoke_origin({module, fun, args}, conn) when is_atom(module) and is_atom(fun) and is_list(args),
    do: apply(module, fun, [conn | args])

  defp invoke_origin(_other, _conn), do: nil

  # The authorization server is advertised verbatim: an issuer identifier is
  # compared by exact string match (RFC 8414 / OIDC Discovery), so - unlike a
  # resource origin - its trailing slash MUST be preserved or discovery breaks.
  #
  # A blank explicit `:issuer` is ignored (falls through to `:config`) rather
  # than publishing `[""]` or overriding a valid configured issuer.
  defp configured_issuer(opts) do
    case Keyword.get(opts, :issuer) do
      issuer when is_binary(issuer) and issuer != "" -> issuer
      _ -> config_issuer(Keyword.get(opts, :config))
    end
  end

  defp config_issuer(%Config{issuer: issuer}) when is_binary(issuer), do: issuer
  defp config_issuer(fun) when is_function(fun, 0), do: config_issuer(fun.())
  defp config_issuer({module, fun}) when is_atom(module) and is_atom(fun), do: config_issuer(apply(module, fun, []))

  defp config_issuer({module, fun, args}) when is_atom(module) and is_atom(fun) and is_list(args),
    do: config_issuer(apply(module, fun, args))

  defp config_issuer(_), do: nil

  defp base_url(%Plug.Conn{} = conn) do
    scheme = Atom.to_string(conn.scheme)
    scheme <> "://" <> conn.host <> port_suffix(scheme, conn.port)
  end

  defp port_suffix("https", 443), do: ""
  defp port_suffix("http", 80), do: ""
  defp port_suffix(_scheme, port), do: ":" <> Integer.to_string(port)

  defp normalize_path("/" <> _rest = path), do: path
  defp normalize_path(path), do: "/" <> path
end
