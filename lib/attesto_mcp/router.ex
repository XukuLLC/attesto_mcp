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

  ## Single resource

      defmodule MyAppWeb.Router do
        use Phoenix.Router
        use AttestoMCP.Router

        scope "/" do
          pipe_through :api
          attesto_mcp_protected_resource_metadata "/mcp", scopes: ["mcp:tools:call"]
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
  Choose explicitly with `:root` (see `attesto_mcp_protected_resource_metadata/2`);
  a second resource that leaves the root implicit raises a compile error.

      # Serve no root document (each endpoint's WWW-Authenticate already points
      # clients at its own path-suffixed metadata):
      attesto_mcp_protected_resource_metadata "/mcp/foo", scopes: ["foo:mcp:tools:call"], root: false
      attesto_mcp_protected_resource_metadata "/mcp/bar", scopes: ["bar:mcp:tools:call"], root: false

      # Or nominate one resource as the root for legacy clients:
      attesto_mcp_protected_resource_metadata "/mcp/foo", scopes: ["foo:mcp:tools:call"], root: true
      attesto_mcp_protected_resource_metadata "/mcp/bar", scopes: ["bar:mcp:tools:call"]

  ## Options

  Options are forwarded to `AttestoMCP.Metadata.protected_resource/3`. The most
  common is `:scopes` (served as `scopes_supported`); `:authorization_servers`,
  `:resource_name`, `:tls_client_certificate_bound_access_tokens`, and the other
  RFC 9728 fields are also accepted.

  ## Pinning the origin behind a proxy

  By default the served `resource` and `authorization_servers` are derived from
  the live request connection. Behind a TLS-terminating reverse proxy that is
  fragile (`http`/internal host) and spoofable (`X-Forwarded-Host`). Pass
  `:base_url` (or `:origin`) to pin the origin instead - a `String.t()`, a
  `&Mod.fun/1` capture, or a `{Mod, :fun}` tuple resolved at request time. Route
  `private` is compiled, so use a string, a remote function capture, or an MFA
  tuple - not an anonymous `fn`:

      attesto_mcp_protected_resource_metadata "/mcp",
        scopes: ["mcp:tools:call"],
        base_url: "https://mcp.example.com"

  `AttestoMCP.Plug.ProtectResource` accepts the same `:base_url`/`:origin`, so
  the challenge URL and the served metadata stay aligned. See
  `guides/proxy_origin.md`.
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
      ambiguous and is NOT mounted implicitly: auto-mounting it to whichever
      resource happened to be declared first could publish a sensitive
      resource's metadata at a guessable path by accident. A second declaration
      that leaves the root implicit raises a compile error telling the host to
      choose.

  Set `:root` to control it explicitly:

    * `root: true` — mount the root document for THIS resource (one resource may
      claim it; a second `root: true` is a compile error).
    * `root: false` — never mount the root for this resource. With every
      resource set to `false`, no root document is served at all.
  """
  defmacro attesto_mcp_protected_resource_metadata(resource_path, opts \\ []) do
    quote bind_quoted: [resource_path: resource_path, opts: opts] do
      {root_choice, metadata_opts} = Keyword.pop(opts, :root, :auto)

      private = %{
        attesto_mcp_metadata_opts: metadata_opts,
        attesto_mcp_resource_path: resource_path
      }

      get "/.well-known/oauth-protected-resource" <> resource_path,
          AttestoMCP.MetadataController,
          :show,
          private: private

      # `AttestoMCP.Router.mount_root?/2` runs the compile-time bookkeeping (and
      # raises on an ambiguous implicit root); we only emit the route here.
      if AttestoMCP.Router.mount_root?(__MODULE__, root_choice) do
        get "/.well-known/oauth-protected-resource",
            AttestoMCP.MetadataController,
            :show,
            private: private
      end
    end
  end

  @doc false
  # Decide (at compile time) whether the unsuffixed root document should be
  # mounted for the resource currently being declared, given the host's `:root`
  # choice and the routes declared so far on `module`. Updates the tracking
  # attributes and raises when more than one resource would leave the root's
  # resource implicit/order-dependent.
  @spec mount_root?(module(), boolean() | :auto) :: boolean()
  def mount_root?(module, root_choice) do
    count = Module.get_attribute(module, :attesto_mcp_resource_count) + 1
    Module.put_attribute(module, :attesto_mcp_resource_count, count)

    mounted? = Module.get_attribute(module, :attesto_mcp_root_mounted)
    explicit? = Module.get_attribute(module, :attesto_mcp_root_explicit)

    mount? = decide_root(root_choice, count, mounted?, explicit?)

    if root_choice in [true, false], do: Module.put_attribute(module, :attesto_mcp_root_explicit, true)
    if mount?, do: Module.put_attribute(module, :attesto_mcp_root_mounted, true)

    mount?
  end

  defp decide_root(true, _count, true = _mounted?, _explicit?) do
    raise ArgumentError,
          "attesto_mcp_protected_resource_metadata: root: true was given for more than one resource, " <>
            "but only one resource may answer GET /.well-known/oauth-protected-resource."
  end

  defp decide_root(true, _count, _mounted?, _explicit?), do: true
  defp decide_root(false, _count, _mounted?, _explicit?), do: false

  # Single-resource convenience: auto-mount the root for the sole resource.
  defp decide_root(:auto, 1, _mounted?, _explicit?), do: true

  # A second-or-later resource with no explicit :root. If the root was
  # auto-mounted to the first resource it is now ambiguous - refuse rather than
  # silently publish an order-dependent root. If the host already chose the root
  # explicitly (root: true/false somewhere), this extra resource mounts nothing.
  defp decide_root(:auto, _count, true = _mounted?, false = _explicit?) do
    raise ArgumentError,
          "attesto_mcp_protected_resource_metadata: more than one protected resource is declared, so " <>
            "the root GET /.well-known/oauth-protected-resource document's resource is ambiguous. Pass " <>
            "root: true on the resource that should answer it (or root: false on each to serve no root)."
  end

  defp decide_root(:auto, _count, _mounted?, _explicit?), do: false
end
