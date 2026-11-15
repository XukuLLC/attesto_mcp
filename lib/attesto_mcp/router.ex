defmodule AttestoMCP.Router do
  @moduledoc """
  Phoenix router macros for OAuth protected-resource metadata discovery.

  The MCP authorization spec treats a protected HTTP MCP server as an OAuth
  resource server. Clients discover where to authorize by fetching RFC 9728
  protected-resource metadata from a well-known location derived from the
  resource path: `/.well-known/oauth-protected-resource/<resource-path>` (and,
  for clients that predate the path-suffixed form, the root
  `/.well-known/oauth-protected-resource`).

  `use AttestoMCP.Router` imports `attesto_mcp_protected_resource_metadata/2`,
  which mounts both routes for a resource at `AttestoMCP.MetadataController`. The
  served `resource` identifier is the resource origin (`:base_url`/`:origin` if
  pinned, otherwise the request origin) joined with the resource path - the same
  value `AttestoMCP.Plug.ProtectResource` advertises in its `WWW-Authenticate`
  `resource_metadata` challenge, so discovery and challenge agree when both are
  given the same origin (see "Pinning the origin behind a proxy" below).

  These routes only publish metadata; they do not configure token verification.
  The protected endpoint must separately configure `:resource_audience` or
  `:trusted_audiences` on `AttestoMCP.Plug.Authenticate` / `ProtectResource`.
  Prefer `resource_audience: :resource` with the same pinned origin and resource
  path. The metadata macro itself does not require an audience policy.

  ## Single resource

      defmodule MyAppWeb.Router do
        use Phoenix.Router
        use AttestoMCP.Router

        scope "/" do
          pipe_through :api
          attesto_mcp_protected_resource_metadata "/mcp",
            scopes: ["mcp:tools:call"],
            config: {MyApp.Attesto, :config},
            base_url: "https://mcp.example.com"
        end
      end

  This serves:

    * `GET /.well-known/oauth-protected-resource/mcp`
    * `GET /.well-known/oauth-protected-resource` (root compatibility document,
      auto-mounted for the single resource)

  ## Multiple resources

  Declare one call per protected resource. Each gets its own path-suffixed
  well-known route and its own metadata document. The unsuffixed root document
  is NOT auto-mounted once more than one resource exists - its resource would be
  ambiguous, and auto-mounting it to whichever resource was declared first could
  publish a sensitive resource's metadata at a guessable path by accident.
  Choose explicitly with `:root` (see `attesto_mcp_protected_resource_metadata/2`).
  If the first resource used the single-resource default, adding any second
  resource raises until the first declaration makes root ownership explicit.

      # Serve no root document (each endpoint's WWW-Authenticate already points
      # clients at its own path-suffixed metadata):
      attesto_mcp_protected_resource_metadata "/mcp/foo",
        scopes: ["foo:mcp:tools:call"], config: {MyApp.Attesto, :config}, root: false
      attesto_mcp_protected_resource_metadata "/mcp/bar",
        scopes: ["bar:mcp:tools:call"], config: {MyApp.Attesto, :config}, root: false

      # Or nominate one resource as the root for legacy clients:
      attesto_mcp_protected_resource_metadata "/mcp/foo",
        scopes: ["foo:mcp:tools:call"], config: {MyApp.Attesto, :config}, root: true
      attesto_mcp_protected_resource_metadata "/mcp/bar",
        scopes: ["bar:mcp:tools:call"], config: {MyApp.Attesto, :config}

  ## Options

  Options are forwarded to `AttestoMCP.Metadata.protected_resource/3`. The most
  common is `:scopes` (served as `scopes_supported`). One of `:config`, `:issuer`,
  or `:authorization_servers` is required so the authorization server never
  comes from the request `Host`. `:resource_name`,
  `:tls_client_certificate_bound_access_tokens`, and the other RFC 9728 fields
  are also accepted.

  ## Pinning the origin behind a proxy

  By default the served `resource` is derived from the live request connection;
  `authorization_servers` is always explicit or comes from the configured
  issuer. Behind a TLS-terminating reverse proxy, request-derived resource
  origins are fragile (`http`/internal host) and spoofable (`Host` or rewritten
  `X-Forwarded-Host`). Pass `:base_url` (or `:origin`) to pin the origin - a `String.t()`, a
  `&Mod.fun/1` capture, or a `{Mod, :fun}` tuple resolved at request time. Route
  `private` is compiled, so use a string, a remote function capture, or an MFA
  tuple - not an anonymous `fn`:

      attesto_mcp_protected_resource_metadata "/mcp",
        scopes: ["mcp:tools:call"],
        config: {MyApp.Attesto, :config},
        base_url: "https://mcp.example.com"

  `AttestoMCP.Plug.ProtectResource` accepts the same `:base_url`/`:origin`, so
  the challenge URL and the served metadata stay aligned. See
  `guides/proxy_origin.md`.

  ## Combined AS+RS hosts (attesto_phoenix in the same app)

  A host that also mounts `attesto_phoenix`'s
  `AttestoPhoenix.Router.attesto_routes/1` already serves a root
  `/.well-known/oauth-protected-resource` document. Pick ONE owner per PRM
  route:

    * Single resource, AS and RS in one app: prefer
      `attesto_routes(protected_resource_paths: ["/mcp"])` over this macro -
      it mounts both the root and the path-inserted form from the same
      controller, with the RFC 9728 §3.3 `resource`-consistency guard.
    * Standalone RS, or multiple resources: use this macro. If the AS half
      also runs in the same app, pass `root: false` here or
      `protected_resource_root: false` to `attesto_routes` so the root
      document has exactly one owner.

  Phoenix's duplicate-route behavior (first match wins, with a compile
  warning) is only the backstop - mounting the same well-known path from both
  packages is a wiring smell, not a supported configuration.
  """

  @doc false
  defmacro __using__(_opts) do
    quote do
      import AttestoMCP.Router

      # Whether the root compatibility document has been mounted, and whether the
      # host chose its resource explicitly (`root: true`/`false`) vs the
      # single-resource auto-mount. `:resource_count` lets the macro detect that
      # a second resource has been declared and refuse to keep an implicit,
      # order-dependent root (see `attesto_mcp_protected_resource_metadata/2`).
      Module.register_attribute(__MODULE__, :attesto_mcp_root_mounted, accumulate: false)
      Module.put_attribute(__MODULE__, :attesto_mcp_root_mounted, false)
      Module.register_attribute(__MODULE__, :attesto_mcp_root_explicit, accumulate: false)
      Module.put_attribute(__MODULE__, :attesto_mcp_root_explicit, false)
      Module.register_attribute(__MODULE__, :attesto_mcp_resource_count, accumulate: false)
      Module.put_attribute(__MODULE__, :attesto_mcp_resource_count, 0)
    end
  end

  @doc """
  Mount the RFC 9728 protected-resource metadata routes for one MCP resource.

  `resource_path` is the path of the protected MCP endpoint, for example
  `"/mcp"` or `"/mcp/brokers"`. `opts` are forwarded to
  `AttestoMCP.Metadata.protected_resource/3`; pass `:scopes` to advertise the
  scopes the resource requires.

  ## The root compatibility document (`root:`)

  RFC 9728 §3.1 path-suffixed metadata
  (`/.well-known/oauth-protected-resource<resource-path>`) is the current form;
  the unsuffixed root `/.well-known/oauth-protected-resource` exists only for
  clients that predate it. Each protected endpoint's `WWW-Authenticate`
  challenge already points clients at its own path-suffixed document, so the
  root is never required.

    * A **single-resource** router auto-mounts the root for its one resource (a
      convenience for the common case).
    * Once **more than one** resource is declared, the root's resource is
      ambiguous and is NOT allowed to remain implicitly assigned: auto-mounting
      it to whichever resource happened to be declared first could publish a
      sensitive resource's metadata at a guessable path by accident. If the
      first declaration used the default, adding a second resource raises until
      the first declaration sets `root: true` or `root: false` explicitly.

  Set `:root` to control it explicitly:

    * `root: true` — mount the root document for THIS resource (one resource may
      claim it; a second `root: true` is a compile error).
    * `root: false` — never mount the root for this resource. With every
      resource set to `false`, no root document is served at all.
  """
  defmacro attesto_mcp_protected_resource_metadata(resource_path, opts \\ []) do
    quote bind_quoted: [resource_path: resource_path, opts: opts] do
      if Phoenix.Router.scoped_path(__MODULE__, "/") != "/" do
        raise ArgumentError,
              "attesto_mcp_protected_resource_metadata must be declared at the router root; " <>
                "place it inside `scope \"/\" do ... end` rather than a path-prefixed scope"
      end

      {resource_path, root_choice, metadata_opts} = Attesto.ResourceMetadata.mount_options(resource_path, opts)

      private = %{
        attesto_mcp_metadata_opts: metadata_opts,
        attesto_mcp_resource_path: resource_path
      }

      metadata_path = AttestoMCP.Metadata.protected_resource_metadata_path(resource_path)
      root_metadata_path = AttestoMCP.Metadata.protected_resource_metadata_path("/")

      get metadata_path,
          AttestoMCP.MetadataController,
          :show,
          private: private

      # `AttestoMCP.Router.mount_root?/2` runs the compile-time bookkeeping (and
      # raises on an ambiguous implicit root); we only emit the route here.
      if AttestoMCP.Router.mount_root?(__MODULE__, root_choice) and
           metadata_path != root_metadata_path do
        get root_metadata_path,
            AttestoMCP.MetadataController,
            :show,
            private: private
      end
    end
  end

  @doc false
  @spec normalize_resource_path!(term()) :: String.t()
  defdelegate normalize_resource_path!(resource_path), to: AttestoMCP.Metadata

  @doc false
  @spec protected_resource_metadata_path(String.t()) :: String.t()
  defdelegate protected_resource_metadata_path(resource_path), to: AttestoMCP.Metadata

  @doc false
  # Decide (at compile time) whether the unsuffixed root document should be
  # mounted for the resource currently being declared, given the host's `:root`
  # choice and the routes declared so far on `module`. Updates the tracking
  # attributes and raises when more than one resource would leave the root's
  # resource implicit/order-dependent.
  @spec mount_root?(module(), boolean() | :auto) :: boolean()
  def mount_root?(module, root_choice) do
    state = %{
      count: Module.get_attribute(module, :attesto_mcp_resource_count),
      mounted?: Module.get_attribute(module, :attesto_mcp_root_mounted),
      explicit?: Module.get_attribute(module, :attesto_mcp_root_explicit)
    }

    {mount?, next} = Attesto.ResourceRoutes.mount(root_choice, state)
    Module.put_attribute(module, :attesto_mcp_resource_count, next.count)
    Module.put_attribute(module, :attesto_mcp_root_mounted, next.mounted?)
    Module.put_attribute(module, :attesto_mcp_root_explicit, next.explicit?)
    mount?
  rescue
    error in ArgumentError ->
      reraise %{
                error
                | message:
                    String.replace(
                      error.message,
                      "protected_resource_metadata:",
                      "attesto_mcp_protected_resource_metadata:"
                    )
              },
              __STACKTRACE__
  end
end
