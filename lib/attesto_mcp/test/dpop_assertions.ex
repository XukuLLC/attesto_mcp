if Code.ensure_loaded?(ExUnit.Assertions) do
  defmodule AttestoMCP.Test.DPoPAssertions do
    @moduledoc """
    Shipped ExUnit assertions for the DPoP sender-constraint contract.

    RFC 9449 binds an access token to the client key that signed a DPoP proof
    via the token's `cnf.jkt` claim (RFC 7800). Two properties of that contract
    are worth a host MCP server proving on its own pipeline, because getting
    either wrong silently downgrades sender-constrained tokens to bearer tokens:

      1. A DPoP-bound token presented as a plain `Bearer` token (no proof) MUST
        be rejected. Otherwise a captured token is usable without the key.
      2. A DPoP-bound token presented as `DPoP` with a valid proof for the live
        request MUST be accepted.

    These helpers drive a host's already-wired authentication plug against both
    cases so the host's exact `:config`, `:replay_check`, `:htu`, and error
    rendering are exercised. They build the token and proof with
    `AttestoMCP.Test.Factory` and use only Attesto's published DPoP API
    (`Attesto.DPoP.compute_ath/1` via the factory), so they do not depend on any
    Attesto-internal test scaffolding.

    The module is shipped for downstream test suites when `ExUnit` is
    available.

    ## Usage

        defmodule MyApp.MCPAuthTest do
          use ExUnit.Case
          import AttestoMCP.Test.DPoPAssertions

          setup do
            %{config: AttestoMCP.Test.Factory.config()}
          end

          test "MCP endpoint enforces DPoP binding", %{config: config} do
            plug = fn conn ->
              MyAppWeb.MCPAuth.call(conn, MyAppWeb.MCPAuth.init([]))
            end

            assert_dpop_bound_bearer_rejected(plug, config)
            assert_dpop_proof_accepted(plug, config)
          end
        end

    `plug_fun` is a one-arity function that runs the host's authentication
    pipeline on a `Plug.Conn` and returns the resulting conn. A host that
    requires `:replay_check` for DPoP requests must wire it inside `plug_fun`.
    """

    import ExUnit.Assertions
    import Plug.Conn, only: [put_req_header: 3]
    import Plug.Test, only: [conn: 3]

    alias AttestoMCP.Test.Factory

    @type plug_fun :: (Plug.Conn.t() -> Plug.Conn.t())

    @doc """
    Assert that a DPoP-bound token presented as a plain `Bearer` token (with no
    proof) is rejected by the host pipeline.

    Options:

      * `:path` - request path (default `"/mcp"`).
      * `:method` - request method (default `:post`).
      * `:scopes` - scopes minted into the token (default the factory default).

    Returns the resulting halted `Plug.Conn` for further assertions.
    """
    @spec assert_dpop_bound_bearer_rejected(plug_fun(), Attesto.Config.t(), keyword()) :: Plug.Conn.t()
    def assert_dpop_bound_bearer_rejected(plug_fun, config, opts \\ []) when is_function(plug_fun, 1) do
      jkt = Factory.dpop_jwk() |> Factory.dpop_jkt()
      token = Factory.access_token(config, token_opts(opts, dpop_jkt: jkt))

      conn =
        opts
        |> base_conn()
        |> put_req_header("authorization", "Bearer " <> token)
        |> plug_fun.()

      assert conn.halted,
             "expected a DPoP-bound token presented as Bearer to be rejected, but the pipeline let it through"

      conn
    end

    @doc """
    Assert that a DPoP-bound token presented as `DPoP` with a valid proof for
    the live request is accepted by the host pipeline.

    Options:

      * `:path` - request path (default `"/mcp"`).
      * `:method` - request method (default `:post`).
      * `:scopes` - scopes minted into the token (default the factory default).
      * `:htu` - the `htu` claim of the proof (default the factory audience). It
        must match the host's computed request URI.

    Returns the resulting non-halted `Plug.Conn` for further assertions.
    """
    @spec assert_dpop_proof_accepted(plug_fun(), Attesto.Config.t(), keyword()) :: Plug.Conn.t()
    def assert_dpop_proof_accepted(plug_fun, config, opts \\ []) when is_function(plug_fun, 1) do
      jwk = Factory.dpop_jwk()
      jkt = Factory.dpop_jkt(jwk)
      token = Factory.access_token(config, token_opts(opts, dpop_jkt: jkt))
      {proof, ^jkt} = Factory.dpop_proof(token, proof_opts(opts, jwk: jwk))

      conn =
        opts
        |> base_conn()
        |> put_req_header("authorization", "DPoP " <> token)
        |> put_req_header("dpop", proof)
        |> plug_fun.()

      refute conn.halted,
             "expected a DPoP-bound token presented with a valid proof to be accepted, but the pipeline rejected it"

      conn
    end

    defp base_conn(opts) do
      method = Keyword.get(opts, :method, :post)
      path = Keyword.get(opts, :path, "/mcp")
      conn(method, path, nil)
    end

    defp token_opts(opts, extra) do
      case Keyword.fetch(opts, :scopes) do
        {:ok, scopes} -> Keyword.put(extra, :scopes, scopes)
        :error -> extra
      end
    end

    defp proof_opts(opts, extra) do
      case Keyword.fetch(opts, :htu) do
        {:ok, htu} -> Keyword.put(extra, :htu, htu)
        :error -> extra
      end
    end
  end
end
