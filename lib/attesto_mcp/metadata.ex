defmodule AttestoMCP.Metadata do
  @moduledoc """
  Builders for OAuth metadata used by HTTP MCP authorization.

  MCP HTTP servers that require authorization act as OAuth protected resources.
  The MCP authorization spec points clients at RFC 9728 protected-resource
  metadata first, then at RFC 8414 authorization-server metadata. This module
  builds those documents without coupling the package to any MCP server SDK.

  ## Origin pinning behind a proxy

  The `resource` identifier identifies this server, while
  `authorization_servers` identifies the issuer a client must use to obtain a
  token. A resource identifier may be derived from the live connection when it
  is used only for discovery. Any authentication policy that derives its token
  audience from the resource identifier must pin the origin.

  Behind a TLS-terminating reverse proxy that derivation is both fragile and a
  spoofing vector: `conn.scheme` is often `http`, and `conn.host` reflects the
  request `Host` or whatever `X-Forwarded-*` rewriting produced. An attacker
  can therefore influence an unpinned `resource`. Pin the resource origin when
  it drives authorization policy, and identify the authorization server from a
  trusted configuration source:

    * The **`resource`** identifier and the well-known metadata URL use
      `resolve_origin/2` - the *resource server* origin, pinned via `:base_url`
      or `:origin` (a `String.t()`, a `(Plug.Conn.t() -> String.t())` callback,
      or a `{module, fun}` / `{module, fun, args}` tuple), falling back to the
      live request origin only when neither option is present. An explicitly
      configured pin that is invalid raises instead of falling back.
    * **`authorization_servers`** defaults to the `:config` issuer (or an
      explicit `:issuer` string) when one is supplied - the authorization server
      the host already trusts for token verification, advertised verbatim - and
      otherwise must be supplied explicitly with `:authorization_servers`.
      The issuer is deliberately NOT used as the `resource` origin: RFC 9728
      keeps the protected resource and its authorization server distinct, and
      in a FAPI deployment they are usually different hosts.

  Either can still be overridden outright with an explicit `:resource` /
  `:authorization_servers` opt. See `guides/proxy_origin.md` for the recipe.
  """

  alias Attesto.ResourceMetadata
  alias AttestoMCP.Scopes

  @doc """
  Build an RFC 9728 protected-resource metadata document.

  Required options:

    * `:resource` - an absolute HTTPS protected resource identifier with no
      fragment, usually the canonical MCP server URI such as
      `"https://mcp.example.com/mcp"`. Pass `allow_http: true` for a deliberate
      local development endpoint.
    * `:authorization_servers` - a non-empty, unique list of HTTPS issuer
      identifiers with no query or fragment.

  Common options include `:scopes_supported`, `:bearer_methods_supported`,
  `:dpop_signing_alg_values_supported`, and
  `:tls_client_certificate_bound_access_tokens`.

  `:dpop_signing_alg_values_supported` defaults to every DPoP algorithm
  Attesto verifies. A resource that accepts only Bearer tokens passes `false`
  (or `[]`) to leave the member out of the document; RFC 9728 §3.2 does not
  allow publishing it as an empty array.

  Pass `:authenticate` with the option list given to
  `AttestoMCP.Plug.ProtectResource` (or `AttestoMCP.Plug.Authenticate`) to have
  that default follow the plug: when those options cannot accept a DPoP request
  (`Attesto.Plug.Authenticate.accepts_dpop?/1`), the member is left out. An
  explicit `:dpop_signing_alg_values_supported` takes precedence.
  """
  def protected_resource(opts), do: ResourceMetadata.protected_resource(profile(opts))

  @doc """
  Build protected-resource metadata from a Plug connection and resource path.

  `resource_path` is the path of the MCP endpoint, for example `"/mcp"` or
  `"/mcp/admin"`. The `resource` identifier is `resolve_origin/2` (the resource
  server origin, pinned via `:base_url`/`:origin`) joined with that path.
  `:authorization_servers` defaults to the `:config` issuer (or an explicit
  `:issuer` string) when one is given. One of those sources is required; the
  authorization server is never inferred from the request authority.

  An explicit `:resource` or `:authorization_servers` opt overrides the derived
  value, and short-circuits its derivation: a pinned origin / issuer callback is
  not invoked (and cannot fail) for a value the host supplied outright.
  """
  def protected_resource(conn, path, opts \\ []), do: ResourceMetadata.protected_resource(conn, path, profile(opts))

  @doc false
  # MCP metadata defaults, and the refusal of refresh-token scopes.
  def profile(opts) do
    if is_list(Keyword.get(opts, :scopes_supported)),
      do: Scopes.reject_offline_access!(Keyword.get(opts, :scopes_supported), "scopes_supported")

    opts
    |> default(:bearer_methods_supported, ["header"])
    |> default(:scopes_supported, Scopes.all())
  end

  defp default(opts, key, value), do: if(is_nil(Keyword.get(opts, key)), do: Keyword.put(opts, key, value), else: opts)

  @doc """
  Build the well-known metadata URL for an MCP resource path.

      iex> AttestoMCP.Metadata.protected_resource_url("https://mcp.example.com", "/mcp")
      "https://mcp.example.com/.well-known/oauth-protected-resource/mcp"

  A Plug connection can also be passed as the first argument. The legacy
  two-argument connection form remains available; new code should pass an
  options list as the third argument so origin pinning is explicit.
  """
  defdelegate protected_resource_url(base, path), to: ResourceMetadata

  @doc """
  Build the well-known metadata URL, resolving the origin via `resolve_origin/2`.

  Pass `:base_url`/`:origin` in `opts` to pin the resource origin (so the
  challenge URL matches a pinned `resource`); with no such opt the live request
  origin is used.
  """
  defdelegate protected_resource_url(conn, path, opts), to: ResourceMetadata

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

  When neither pin is present, the request origin is used. Once either option is
  present, it is configuration: invalid literal values and invalid callback
  results raise instead of falling back to the request authority. A trailing
  slash is trimmed so the result joins cleanly with a resource path.
  """
  defdelegate resolve_origin(conn, opts), to: ResourceMetadata

  @doc "Delegates to `Attesto.ResourceMetadata.validate_origin_options!/1`."
  defdelegate validate_origin_options!(opts), to: ResourceMetadata

  @doc "Delegates to `Attesto.ResourceMetadata.require_pinned_origin!/1`."
  defdelegate require_pinned_origin!(opts), to: ResourceMetadata

  @doc "Delegates to `Attesto.ResourceMetadata.validate_metadata_options!/1`."
  defdelegate validate_metadata_options!(opts), to: ResourceMetadata

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
  defdelegate resource_identifier(conn, path, opts \\ []), to: ResourceMetadata

  @doc "Delegates to `Attesto.ResourceMetadata.normalize_resource_path!/2`."
  defdelegate normalize_resource_path!(path, opts \\ []), to: ResourceMetadata

  @doc "Delegates to `Attesto.ResourceMetadata.protected_resource_metadata_path/1`."
  defdelegate protected_resource_metadata_path(path), to: ResourceMetadata

  @doc "Delegates to `Attesto.ResourceMetadata.static_pin?/1`."
  defdelegate static_pin?(opts), to: ResourceMetadata

  @doc false
  @deprecated "Use Attesto.Plug.OAuthError's :resource_metadata option"
  defdelegate resource_metadata_param(url), to: ResourceMetadata

  @doc false
  @deprecated "Use Attesto.Plug.OAuthError's :resource_metadata option"
  defdelegate append_resource_metadata(challenge, url), to: ResourceMetadata

  @doc false
  @deprecated "Use Attesto.Discovery.metadata/2"
  defdelegate authorization_server(config, opts \\ []), to: ResourceMetadata
end
