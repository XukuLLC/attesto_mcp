defmodule AttestoMCP.MetadataTest do
  @moduledoc false
  use ExUnit.Case, async: true

  import Plug.Test

  alias AttestoMCP.Metadata
  alias AttestoMCP.Scopes
  alias AttestoMCP.Test.Factory

  test "protected resource metadata includes MCP OAuth handoff fields" do
    metadata =
      Metadata.protected_resource(
        resource: "https://mcp.example.com/mcp",
        authorization_servers: ["https://auth.example.com"],
        acr_values_supported: ["phr"],
        resource_name: "Example MCP server",
        tls_client_certificate_bound_access_tokens: true
      )

    assert metadata["resource"] == "https://mcp.example.com/mcp"
    assert metadata["authorization_servers"] == ["https://auth.example.com"]
    assert metadata["acr_values_supported"] == ["phr"]
    assert Scopes.tools_call() in metadata["scopes_supported"]
    assert metadata["bearer_methods_supported"] == ["header"]
    assert metadata["tls_client_certificate_bound_access_tokens"] == true
  end

  test "protected resource metadata can be derived from a Plug connection" do
    conn = conn(:get, "https://mcp.example.com/.well-known/oauth-protected-resource/mcp/user")

    metadata =
      Metadata.protected_resource(conn, "/mcp/user",
        issuer: "https://auth.example.com",
        scopes_supported: ["mcp:user"]
      )

    assert metadata["resource"] == "https://mcp.example.com/mcp/user"
    assert metadata["authorization_servers"] == ["https://auth.example.com"]
    assert metadata["scopes_supported"] == ["mcp:user"]
  end

  test "protected resource URL can be derived from a Plug connection" do
    conn = conn(:get, "https://mcp.example.com/mcp/user")

    assert Metadata.protected_resource_url(conn, "/mcp/user") ==
             "https://mcp.example.com/.well-known/oauth-protected-resource/mcp/user"

    assert Metadata.protected_resource_url(conn, "/mcp/user", []) ==
             "https://mcp.example.com/.well-known/oauth-protected-resource/mcp/user"
  end

  test "request-derived origins bracket IPv6 host literals" do
    default_port = conn(:get, "https://[::1]/mcp")
    custom_port = conn(:get, "https://[2001:db8::1]:8443/mcp")

    assert Metadata.resolve_origin(default_port, []) == "https://[::1]"

    assert Metadata.protected_resource_url(default_port, "/mcp", []) ==
             "https://[::1]/.well-known/oauth-protected-resource/mcp"

    assert Metadata.resolve_origin(custom_port, []) == "https://[2001:db8::1]:8443"

    assert Metadata.protected_resource(custom_port, "/mcp", issuer: "https://auth.example.com")["resource"] ==
             "https://[2001:db8::1]:8443/mcp"
  end

  test "an explicit :base_url pins the resource origin over the request connection" do
    # Behind a TLS-terminating proxy the conn is http + an internal host; the
    # pinned origin must win so the advertised resource is correct/non-spoofable.
    conn = conn(:get, "http://10.0.0.5/.well-known/oauth-protected-resource/mcp")

    metadata =
      Metadata.protected_resource(conn, "/mcp",
        base_url: "https://mcp.example.com",
        issuer: "https://auth.example.com"
      )

    assert metadata["resource"] == "https://mcp.example.com/mcp"
  end

  test ":origin accepts a (conn -> url) callback resolved at request time" do
    conn = conn(:get, "http://10.0.0.5/.well-known/oauth-protected-resource/mcp")

    metadata =
      Metadata.protected_resource(conn, "/mcp",
        origin: fn _conn -> "https://mcp.example.com" end,
        issuer: "https://auth.example.com"
      )

    assert metadata["resource"] == "https://mcp.example.com/mcp"
  end

  test "authorization_servers defaults to the :config issuer, not the resource origin" do
    conn = conn(:get, "https://mcp.example.com/.well-known/oauth-protected-resource/mcp")

    metadata = Metadata.protected_resource(conn, "/mcp", config: Factory.config())

    # The resource is the resource server's own origin; the AS is the issuer.
    assert metadata["resource"] == "https://mcp.example.com/mcp"
    assert metadata["authorization_servers"] == ["https://auth.example.com"]
  end

  test "an explicit :issuer string sets authorization_servers verbatim (issuer is matched exactly)" do
    conn = conn(:get, "https://mcp.example.com/.well-known/oauth-protected-resource/mcp")

    # An issuer identifier is compared by exact string match, so a trailing slash
    # MUST be preserved - unlike the resource origin, which is trimmed.
    metadata = Metadata.protected_resource(conn, "/mcp", issuer: "https://auth.example.com/tenant/")

    assert metadata["authorization_servers"] == ["https://auth.example.com/tenant/"]
  end

  test "a blank explicit :issuer fails closed at route validation" do
    conn = conn(:get, "https://mcp.example.com/.well-known/oauth-protected-resource/mcp")

    assert_raise ArgumentError, ~r/:issuer/, fn ->
      Metadata.validate_metadata_options!(issuer: "", config: Factory.config())
    end

    assert_raise ArgumentError, ~r/:issuer must be a valid HTTPS issuer/, fn ->
      Metadata.protected_resource(conn, "/mcp", issuer: "", config: Factory.config())
    end
  end

  test "an explicit :resource overrides the derived identifier" do
    conn = conn(:get, "https://mcp.example.com/.well-known/oauth-protected-resource/mcp")

    metadata =
      Metadata.protected_resource(conn, "/mcp",
        resource: "https://canonical.example/mcp",
        issuer: "https://auth.example.com"
      )

    assert metadata["resource"] == "https://canonical.example/mcp"
  end

  test "protected_resource_url/3 pins the origin via :base_url" do
    conn = conn(:get, "http://10.0.0.5/mcp")

    assert Metadata.protected_resource_url(conn, "/mcp", base_url: "https://mcp.example.com") ==
             "https://mcp.example.com/.well-known/oauth-protected-resource/mcp"
  end

  test "resolve_origin/2 falls back to the request origin and trims a pinned trailing slash" do
    conn = conn(:get, "https://mcp.example.com/x")

    assert Metadata.resolve_origin(conn, []) == "https://mcp.example.com"
    assert Metadata.resolve_origin(conn, base_url: "https://canonical.example/") == "https://canonical.example"
  end

  test ":base_url accepts an {module, fun} tuple resolved at request time" do
    conn = conn(:get, "http://10.0.0.5/.well-known/oauth-protected-resource/mcp")

    metadata =
      Metadata.protected_resource(conn, "/mcp",
        base_url: {__MODULE__, :pinned_origin},
        issuer: "https://auth.example.com"
      )

    assert metadata["resource"] == "https://mcp.example.com/mcp"
  end

  def pinned_origin(_conn), do: "https://mcp.example.com"

  test "a configured blank :base_url fails closed instead of falling back" do
    conn = conn(:get, "https://request-host.example/.well-known/oauth-protected-resource/mcp")

    assert_raise ArgumentError, ~r/:base_url/, fn ->
      Metadata.protected_resource(conn, "/mcp",
        base_url: "",
        origin: "https://canonical.example",
        issuer: "https://auth.example.com"
      )
    end

    assert_raise ArgumentError, ~r/:base_url/, fn ->
      Metadata.resolve_origin(conn, base_url: "")
    end
  end

  test "a malformed :base_url raises instead of using the request Host or lower-precedence origin" do
    conn = conn(:get, "https://request-host.example/.well-known/oauth-protected-resource/mcp")

    bad_pins = [
      "/",
      "///",
      "/prefix",
      "mcp.example.com",
      "",
      "://x",
      "https:///path",
      "ftp://x",
      "https://",
      ~s(https://host"),
      "https://host\\",
      "https://host\r\nx",
      "https://user:pass@host",
      "https://host?x=1",
      "https://host#frag",
      "https://host/%zz"
    ]

    for bad <- bad_pins do
      assert_raise ArgumentError, ~r/:base_url/, fn ->
        Metadata.protected_resource(conn, "/mcp", base_url: bad, issuer: "https://auth.example.com")
      end
    end

    assert_raise ArgumentError, ~r/:base_url/, fn ->
      Metadata.resolve_origin(conn, base_url: "/", origin: "https://canonical.example")
    end

    # A port and a path prefix (path-prefix proxy) are legitimate and accepted.
    with_port =
      Metadata.protected_resource(conn, "/mcp",
        base_url: "http://mcp.example.com:4000/base",
        authorization_servers: ["https://auth.example.com"],
        allow_http: true
      )

    assert with_port["resource"] == "http://mcp.example.com:4000/base/mcp"
  end

  test "the resource origin callback is resolved once and never defines authorization_servers" do
    conn = conn(:get, "https://request-host.example/.well-known/oauth-protected-resource/mcp")
    {:ok, counter} = Agent.start_link(fn -> 0 end)

    origin = fn _conn ->
      Agent.update(counter, &(&1 + 1))
      "https://pinned.example"
    end

    metadata = Metadata.protected_resource(conn, "/mcp", base_url: origin, issuer: "https://auth.example.com")

    assert metadata["resource"] == "https://pinned.example/mcp"
    assert metadata["authorization_servers"] == ["https://auth.example.com"]
    assert Agent.get(counter, & &1) == 1
  end

  test "refuses to infer authorization_servers from the request authority" do
    conn = conn(:get, "https://attacker.example/.well-known/oauth-protected-resource/mcp")

    assert_raise ArgumentError, ~r/request Host cannot define the authorization server/, fn ->
      Metadata.validate_metadata_options!([])
    end

    assert_raise ArgumentError, ~r/requires :authorization_servers/, fn ->
      Metadata.protected_resource(conn, "/mcp")
    end
  end

  test "a :config issuer with a trailing slash is advertised verbatim" do
    conn = conn(:get, "https://mcp.example.com/.well-known/oauth-protected-resource/mcp")
    config = %{Factory.config() | issuer: "https://auth.example.com/tenant/"}

    metadata = Metadata.protected_resource(conn, "/mcp", config: config)

    assert metadata["authorization_servers"] == ["https://auth.example.com/tenant/"]
  end

  test "an explicit :resource / :authorization_servers short-circuits lower-precedence callbacks" do
    conn = conn(:get, "https://mcp.example.com/.well-known/oauth-protected-resource/mcp")

    # Both values are supplied outright, so the origin and config callbacks - which
    # would raise - must never be invoked.
    metadata =
      Metadata.protected_resource(conn, "/mcp",
        resource: "https://canonical.example/mcp",
        authorization_servers: ["https://auth.example.com"],
        base_url: fn _conn -> raise "origin callback should not run" end,
        config: fn -> raise "config callback should not run" end
      )

    assert metadata["resource"] == "https://canonical.example/mcp"
    assert metadata["authorization_servers"] == ["https://auth.example.com"]
  end

  test "rejects malformed protected-resource identifiers" do
    invalid = [
      nil,
      "",
      "/mcp",
      "https:///mcp",
      "ftp://mcp.example/mcp",
      "https://mcp.example/mcp#fragment",
      "https://mcp.example/%zz",
      <<0xFF>>
    ]

    for resource <- invalid do
      assert_raise ArgumentError, ~r/resource/, fn ->
        Metadata.protected_resource(
          resource: resource,
          authorization_servers: ["https://auth.example.com"]
        )
      end
    end
  end

  test "HTTP resource identifiers require an explicit development opt-in" do
    opts = [
      resource: "http://localhost:4000/mcp",
      authorization_servers: ["https://auth.example.com"]
    ]

    assert_raise ArgumentError, ~r/absolute https URL/, fn ->
      Metadata.protected_resource(opts)
    end

    assert Metadata.protected_resource(Keyword.put(opts, :allow_http, true))["resource"] ==
             "http://localhost:4000/mcp"
  end

  test "requires a non-empty unique list of HTTPS authorization-server issuers" do
    invalid = [
      nil,
      [],
      "https://auth.example.com",
      [""],
      ["http://auth.example.com"],
      ["https:///issuer"],
      ["https://auth.example.com?query=1"],
      ["https://auth.example.com#fragment"],
      [<<0xFF>>],
      ["https://auth.example.com", "https://auth.example.com"]
    ]

    for servers <- invalid do
      assert_raise ArgumentError, ~r/:authorization_servers/, fn ->
        Metadata.protected_resource(
          resource: "https://mcp.example.com/mcp",
          authorization_servers: servers
        )
      end
    end
  end

  test "preserves a valid unique multi-issuer list and meaningful trailing slashes" do
    issuers = ["https://one.example/tenant/", "https://two.example"]

    metadata =
      Metadata.protected_resource(
        resource: "https://mcp.example.com/mcp",
        authorization_servers: issuers
      )

    assert metadata["authorization_servers"] == issuers
  end

  test "the root resource uses the bare well-known URL without a trailing slash" do
    assert Metadata.protected_resource_url("https://mcp.example.com", "/") ==
             "https://mcp.example.com/.well-known/oauth-protected-resource"

    assert Metadata.protected_resource_url("https://mcp.example.com", "/mcp") ==
             "https://mcp.example.com/.well-known/oauth-protected-resource/mcp"
  end

  test "resource paths are normalized once and reject ambiguous components" do
    assert Metadata.normalize_resource_path!("mcp/tools") == "/mcp/tools"

    assert Metadata.protected_resource_metadata_path("mcp/tools") ==
             "/.well-known/oauth-protected-resource/mcp/tools"

    for invalid <- ["/mcp/../admin", "/mcp/./tools", "/mcp?tenant=a", "/mcp#fragment"] do
      assert_raise ArgumentError, ~r/resource_path/, fn ->
        Metadata.normalize_resource_path!(invalid)
      end
    end

    assert_raise ArgumentError, ~r/non-root/, fn ->
      Metadata.normalize_resource_path!("/", allow_root: false)
    end
  end

  test "router path helpers remain callable throughout 2.x" do
    assert AttestoMCP.Router.normalize_resource_path!("mcp/tools") == "/mcp/tools"

    assert AttestoMCP.Router.protected_resource_metadata_path("/mcp/tools") ==
             "/.well-known/oauth-protected-resource/mcp/tools"
  end

  test "authorization server metadata is provided by Attesto discovery" do
    metadata =
      Factory.config()
      |> Attesto.Discovery.metadata(
        authorization_endpoint: "https://auth.example.com/oauth/authorize",
        registration_endpoint: "https://auth.example.com/oauth/register"
      )

    assert metadata["issuer"] == "https://auth.example.com"
    assert metadata["authorization_endpoint"] == "https://auth.example.com/oauth/authorize"
    assert metadata["registration_endpoint"] == "https://auth.example.com/oauth/register"
  end

  test "2.x metadata compatibility helpers remain callable" do
    resource_metadata_param = Function.capture(Metadata, :resource_metadata_param, 1)
    append_resource_metadata = Function.capture(Metadata, :append_resource_metadata, 2)
    authorization_server = Function.capture(Metadata, :authorization_server, 2)

    assert resource_metadata_param.(~s(https://mcp.example/"quoted")) ==
             ~s(resource_metadata="https://mcp.example/\\"quoted\\"")

    assert append_resource_metadata.("Bearer", "https://mcp.example/metadata") ==
             ~s(Bearer, resource_metadata="https://mcp.example/metadata")

    metadata =
      authorization_server.(
        Factory.config(),
        authorization_endpoint: "https://auth.example.com/oauth/authorize"
      )

    assert metadata["issuer"] == "https://auth.example.com"
    assert metadata["authorization_endpoint"] == "https://auth.example.com/oauth/authorize"
  end
end
