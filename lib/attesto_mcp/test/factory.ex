defmodule AttestoMCP.Test.Factory do
  @moduledoc """
  Test fixtures for exercising a host MCP server's Attesto pipeline.

  This factory mints access tokens and DPoP proofs for host application test
  suites, including the shipped `AttestoMCP.Test.DPoPAssertions` helpers. It is
  built entirely on Attesto's published API (`Attesto.Test.DPoP`,
  `Attesto.Token.mint/3`, `Attesto.PrincipalKind.new/3`,
  `Attesto.Config.new/1`, `Attesto.Keystore.Static`) plus JOSE, so it has no
  dependency on any Attesto-internal test scaffolding.

  The module is shipped for downstream ExUnit test suites. `config/0`
  registers an `ExUnit.Callbacks.on_exit/1` cleanup and must be called from
  an ExUnit test process configured with `async: false`, because
  `Attesto.Keystore.Static` uses process-global application configuration.

      defmodule MyApp.MCPAuthTest do
        use ExUnit.Case
        import AttestoMCP.Test.DPoPAssertions

        setup do
          %{config: AttestoMCP.Test.Factory.config()}
        end
      end
  """

  alias Attesto.Keystore.Static
  alias Attesto.Test.DPoP, as: TestDPoP
  alias Attesto.Token
  alias AttestoMCP.Plug.Authenticate

  @issuer "https://auth.example.com"
  @audience "https://mcp.example.com/mcp"
  @subject "usr_123"

  @doc """
  Build an `Attesto.Config` backed by an in-memory `Attesto.Keystore.Static`.

  The signing key is registered into the `:attesto` application environment and
  the previous value is restored via `ExUnit.Callbacks.on_exit/1`, so each test
  gets an isolated keystore. Call this only from a test using `async: false`.
  """
  @spec config() :: Attesto.Config.t()
  def config do
    previous = Application.fetch_env(:attesto, Static)

    ExUnit.Callbacks.on_exit(fn -> restore_static_config(previous) end)
    Application.put_env(:attesto, Static, signing_pem: signing_pem())

    Attesto.Config.new(
      issuer: @issuer,
      audience: @audience,
      keystore: Static,
      principal_kinds: [
        Attesto.PrincipalKind.new("user", "usr_", required_claims: [{"client_id", :non_empty_string}])
      ]
    )
  end

  @doc """
  Mint a signed access token for `config`.

  Options:

    * `:scopes` - scopes granted to the token (default `[AttestoMCP.Scopes.tools_call()]`).
    * `:audience` - scalar or array-valued `aud` claim override. Attesto
      deduplicates the array and collapses a single remaining member to a
      scalar when minting.
    * `:dpop_jkt` - JWK thumbprint to bind the token to (RFC 9449 `cnf.jkt`).
    * `:mtls_cert_thumbprint` - certificate thumbprint to bind the token to (RFC 8705).
  """
  @spec access_token(Attesto.Config.t(), keyword()) :: String.t()
  def access_token(config, opts \\ []) do
    principal = %{
      claims: %{"client_id" => "client-1"},
      kind: "user",
      scopes: Keyword.get(opts, :scopes, [AttestoMCP.Scopes.tools_call()]),
      sub: @subject
    }

    {:ok, token} =
      Token.mint(
        config,
        principal,
        Keyword.take(opts, [:audience, :dpop_jkt, :mtls_cert_thumbprint, :acr, :auth_time])
      )

    token.access_token
  end

  @doc """
  Build a DPoP proof JWT bound to `access_token` and return `{proof, jkt}`.

  `jkt` is the RFC 7638 thumbprint of the proof key, suitable for passing as
  `:dpop_jkt` to `access_token/2`. Options:

    * `:jwk` - reuse a specific key (default a fresh P-256 key).
    * `:htm` - the proof `htm` claim (default `"POST"`).
    * `:htu` - the proof `htu` claim (default the factory audience).
  """
  @spec dpop_proof(String.t(), keyword()) :: {String.t(), String.t()}
  def dpop_proof(access_token, opts \\ []) do
    jwk = Keyword.get_lazy(opts, :jwk, &TestDPoP.generate_key/0)

    proof =
      TestDPoP.proof(
        jwk,
        Keyword.get(opts, :htm, "POST"),
        Keyword.get(opts, :htu, @audience),
        access_token: access_token,
        now: Keyword.get_lazy(opts, :now, &DateTime.utc_now/0),
        jti: Keyword.get_lazy(opts, :jti, fn -> "proof-" <> Integer.to_string(System.unique_integer([:positive])) end)
      )

    {proof, dpop_jkt(jwk)}
  end

  @doc "Generate a fresh P-256 JWK for use as a DPoP proof key."
  @spec dpop_jwk() :: JOSE.JWK.t()
  def dpop_jwk, do: TestDPoP.generate_key()

  @doc "Return the RFC 7638 thumbprint for a DPoP proof key."
  @spec dpop_jkt(JOSE.JWK.t()) :: String.t()
  def dpop_jkt(jwk), do: Attesto.DPoP.compute_jkt(JOSE.JWK.to_public(jwk))

  @doc "Build a self-signed certificate (DER) for exercising mTLS sender constraints."
  @spec self_signed_cert_der() :: binary()
  def self_signed_cert_der do
    %{cert: der} = :public_key.pkix_test_root_cert(~c"CN=attesto-mcp-test", [])
    der
  end

  @doc "The audience the factory mints tokens for, usable as the request `htu`."
  @spec htu() :: String.t()
  def htu, do: @audience

  @doc false
  @spec htu(Plug.Conn.t()) :: String.t()
  def htu(_conn), do: @audience

  @doc "Run the AttestoMCP authentication plug with the factory request URI."
  @spec authenticate(Plug.Conn.t(), Attesto.Config.t(), keyword()) :: Plug.Conn.t()
  def authenticate(conn, config, opts \\ []) do
    opts = Keyword.merge([config: config, htu: &__MODULE__.htu/1], opts)
    Authenticate.call(conn, Authenticate.init(opts))
  end

  @doc false
  @spec form_post(map()) :: Plug.Conn.t()
  def form_post(params) do
    :post
    |> Plug.Test.conn("/mcp", params)
    |> Plug.Conn.put_req_header("content-type", "application/x-www-form-urlencoded")
  end

  defp signing_pem do
    JOSE.JWK.generate_key({:rsa, 2048}) |> JOSE.JWK.to_pem() |> elem(1)
  end

  defp restore_static_config({:ok, config}), do: Application.put_env(:attesto, Static, config)
  defp restore_static_config(:error), do: Application.delete_env(:attesto, Static)
end
