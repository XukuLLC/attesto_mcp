# Pinning the origin behind a reverse proxy

A protected MCP server publishes two origin values a client trusts implicitly:

- the RFC 9728 **`resource`** identifier (the server's own canonical URL), served
  by the metadata endpoint and echoed in the `WWW-Authenticate`
  `resource_metadata` challenge URL, and
- **`authorization_servers`** — *where the client goes to get a token*.

`attesto_mcp` can derive the resource origin from the live request connection
when it is used only for discovery. It never derives `authorization_servers`
from the request authority. A metadata route must supply `:config`, `:issuer`,
or `:authorization_servers`.

## Why deriving from the request is wrong behind a proxy

When TLS is terminated upstream and the app sees proxied requests:

- **Wrong scheme/host.** `conn.scheme` is usually `http` and `conn.host` is
  whatever `X-Forwarded-*` rewriting produced, so the advertised `resource` can
  come out as `http://…` or an internal hostname unless every conn is rewritten
  perfectly.
- **Spoofing.** The request `Host` itself, or a proxy-rewritten
  `X-Forwarded-Host`, can make an unpinned metadata endpoint advertise an
  attacker-controlled `resource`.

When `resource_audience: :resource` is enabled, the resource identifier is also
the token audience policy. AttestoMCP therefore requires a pinned origin for
that policy and raises during plug initialization if it is absent or malformed.
Every authentication boundary requires either `:resource_audience` or an
explicit `:trusted_audiences` policy; a pin or metadata document alone does not
choose one. Origin and audience callbacks must resolve trusted configuration,
never copy an unchecked request `Host` into the audience policy.

## The recipe

Two independent knobs, because RFC 9728 keeps the resource server and its
authorization server distinct (they are usually different hosts under FAPI):

| Value | Knob | Source |
| --- | --- | --- |
| `resource` + challenge URL | `:base_url` / `:origin` | the resource server's own canonical origin |
| `authorization_servers` | `:config` issuer, `:issuer`, or explicit `:authorization_servers` | the trusted authorization server |

`:base_url`/`:origin` accept a `String.t()`, a `(Plug.Conn.t() -> String.t())`
callback, or a `{Mod, :fun}` / `{Mod, :fun, args}` tuple (the conn is prepended
to `args`), resolved at request time. Once either option is present, a blank,
malformed, or non-binary result raises. It never falls back to the request
authority.

The issuer (`authorization_servers`) is advertised **verbatim** — issuer
identifiers are compared by exact string match, so a trailing slash is preserved
(unlike the resource origin, where it is trimmed before joining the path).

### Router (metadata endpoint)

```elixir
defmodule MyAppWeb.Router do
  use Phoenix.Router
  use AttestoMCP.Router

  scope "/" do
    pipe_through :api

    attesto_mcp_protected_resource_metadata "/mcp",
      scopes: ["mcp:tools:call"],
      # pin the resource server origin (resource + well-known URL)
      base_url: "https://mcp.example.com",
      # pin the authorization server the client should use
      config: &MyApp.Attesto.config/0
  end
end
```

Route `private` is compiled, so pass a **string** or a **`&Mod.fun/1` capture**
for `:base_url`/`:origin` — not an anonymous `fn`. The same applies to `:config`
(a `&Mod.config/0` capture works).

### Endpoint (the `WWW-Authenticate` challenge)

Pin the same `:base_url`/`:origin` on `AttestoMCP.Plug.ProtectResource` so the
challenge URL matches the served `resource`:

```elixir
plug AttestoMCP.Plug.ProtectResource,
  config: &MyApp.Attesto.config/0,
  resource_path: "/mcp",
  resource_audience: :resource,
  scopes: [AttestoMCP.Scopes.tools_call()],
  base_url: "https://mcp.example.com"
```

With the origin pinned you do **not** need a bespoke canonical-host guard plug in
front of the metadata routes: a spoofed `Host`/`X-Forwarded-Host` can no longer
change the advertised `resource`, challenge URL, or `authorization_servers`.

### The DPoP target URI

The same pin fixes the URI a DPoP proof must sign (`htu`, RFC 9449 §4.3). On
`AttestoMCP.Plug.ProtectResource` and `AttestoMCP.Plug.Authenticate`, a pinned
`:base_url`/`:origin` makes the `htu` the resolved origin followed by
`conn.request_path`. The request's scheme, `Host`, and port are not consulted,
so a proof made for another server is refused even when the sender puts that
server's name in `Host`, and a proof for the canonical URL verifies even though
the proxy forwarded the request over plain HTTP to an internal name.

| Configuration | DPoP `htu` |
| --- | --- |
| explicit `:htu` callback | whatever the callback returns |
| `:base_url`/`:origin` pinned, no `:htu` | pinned origin + `conn.request_path` |
| neither | `conn.scheme`://`conn.host`:`conn.port` + `conn.request_path` (follows the request `Host`) |

A pinned value with a path prefix (`"https://example.com/tools"`) is joined
with `conn.request_path`, which is correct for a proxy that strips the prefix
before forwarding. When the application sees the full external path, keep the
prefix in `:resource_path` and pin the bare origin. Use an explicit `:htu`
when one endpoint answers on several origins.

### Using a callback

When the canonical origin is computed (multi-tenant, per-deployment config),
pass a capture instead of a literal:

```elixir
# lib/my_app/attesto.ex
def mcp_origin(_conn), do: MyApp.Config.canonical_url()

# router / plug
base_url: &MyApp.Attesto.mcp_origin/1
```

## Discovery-only request derivation

When no `:base_url` or `:origin` is configured, discovery-only resource metadata
may still derive its `resource` from the connection. The authorization server
always requires an explicit source. `resource_audience: :resource` cannot use
request derivation and requires the same canonical pin on the plug and metadata
route.
