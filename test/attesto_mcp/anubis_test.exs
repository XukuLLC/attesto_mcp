defmodule AttestoMCP.AnubisTest do
  @moduledoc false
  # Exercises the Anubis frame-auth bridge. anubis_mcp is an OPTIONAL dependency
  # present in attesto_mcp's own test env, so the compile guard holds and the
  # bridge module is defined here. A host that does not depend on anubis_mcp
  # never compiles `AttestoMCP.Anubis` (see the guard contract test below).
  use ExUnit.Case, async: true

  # A verified `:attesto_context`, shaped exactly as the auth plug assigns it
  # (`:scope` is the granted scopes as a LIST).
  alias Anubis.Server.Frame
  alias AttestoMCP.Anubis.SessionOwnerMismatchError

  defp context do
    %{
      subject: "oc_user-123",
      client_id: "client-abc",
      scope: ["tools:read", "tools:write"],
      claims: %{
        "sub" => "oc_user-123",
        "client_id" => "client-abc",
        "scope" => "tools:read tools:write",
        "iss" => "https://issuer.example",
        "aud" => "https://api.example.com",
        "exp" => 1_234_567_890,
        "iat" => 1_234_567_800
      },
      cnf: nil,
      principal: nil
    }
  end

  defp frame_with(assigns), do: Frame.new(assigns)

  describe "put_auth/1" do
    test "projects a populated context into frame.context.auth in the Anubis shape" do
      frame = frame_with(%{attesto_context: context()})

      auth = AttestoMCP.Anubis.put_auth(frame).context.auth

      assert auth == %{
               sub: "oc_user-123",
               aud: "https://api.example.com",
               scope: "tools:read tools:write",
               scopes: ["tools:read", "tools:write"],
               exp: 1_234_567_890,
               iat: 1_234_567_800,
               client_id: "client-abc",
               raw_claims: context().claims
             }
    end

    test "string scope and list scopes describe the same granted set" do
      frame = frame_with(%{attesto_context: context()})

      auth = AttestoMCP.Anubis.put_auth(frame).context.auth

      assert auth.scope == Enum.join(auth.scopes, " ")
      # And Anubis's own helpers read it correctly.
      assert Frame.scopes(AttestoMCP.Anubis.put_auth(frame)) == ["tools:read", "tools:write"]
      assert Frame.has_scope?(AttestoMCP.Anubis.put_auth(frame), "tools:write")
    end

    test "an empty granted scope set yields an empty string and empty list" do
      ctx = %{context() | scope: []}
      frame = frame_with(%{attesto_context: ctx})

      auth = AttestoMCP.Anubis.put_auth(frame).context.auth
      assert auth.scope == ""
      assert auth.scopes == []
    end

    test "missing :attesto_context leaves the frame unchanged" do
      frame = frame_with(%{})

      assert AttestoMCP.Anubis.put_auth(frame) == frame
      assert AttestoMCP.Anubis.put_auth(frame).context.auth == nil
    end

    test "a non-map :attesto_context is ignored (frame unchanged)" do
      frame = frame_with(%{attesto_context: :garbage})

      assert AttestoMCP.Anubis.put_auth(frame) == frame
    end

    test "a pre-existing frame.context.auth is never overwritten (idempotent)" do
      preset = %{sub: "host-owned", scopes: ["already:set"]}
      frame = frame_with(%{attesto_context: context()})
      frame = %{frame | context: %{frame.context | auth: preset}}

      assert AttestoMCP.Anubis.put_auth(frame).context.auth == preset
    end

    test "calling twice is stable (second call is a no-op)" do
      frame = frame_with(%{attesto_context: context()})

      once = AttestoMCP.Anubis.put_auth(frame)
      assert AttestoMCP.Anubis.put_auth(once) == once
    end

    test "projects a JSON-restored string-keyed context" do
      string_context =
        context()
        |> JSON.encode!()
        |> JSON.decode!()

      frame = frame_with(%{"attesto_context" => string_context})
      projected = AttestoMCP.Anubis.put_auth(frame)

      assert projected.context.auth.sub == "oc_user-123"
      assert projected.context.auth.client_id == "client-abc"
      assert projected.context.auth.scopes == ["tools:read", "tools:write"]
      assert projected.context.auth.raw_claims["iss"] == "https://issuer.example"
    end

    test "supports a custom atom context key" do
      frame = frame_with(%{verified_identity: context()})

      auth = AttestoMCP.Anubis.put_auth(frame, context_key: :verified_identity).context.auth

      assert auth.sub == "oc_user-123"
      assert auth.client_id == "client-abc"
    end

    test "rejects a non-atom custom context key" do
      frame = frame_with(%{attesto_context: context()})

      assert_raise ArgumentError, ~r/context_key/, fn ->
        AttestoMCP.Anubis.put_auth(frame, context_key: "attesto_context")
      end
    end

    test "binds the session to issuer, subject, and client and accepts the same owner" do
      first = frame_with(%{attesto_context: context()}) |> AttestoMCP.Anubis.put_auth()
      next = %{first | context: %{first.context | auth: nil}}

      assert AttestoMCP.Anubis.put_auth(next).context.auth.sub == "oc_user-123"

      assert first.assigns.attesto_mcp_session_owner == %{
               "iss" => "https://issuer.example",
               "sub" => "oc_user-123",
               "client_id" => "client-abc"
             }
    end

    test "rejects a different issuer, subject, or OAuth client on an owner-bound session" do
      first = frame_with(%{attesto_context: context()}) |> AttestoMCP.Anubis.put_auth()

      mismatches = [
        put_in(context(), [:claims, "iss"], "https://other-issuer.example"),
        Map.put(context(), :subject, "other-user"),
        Map.put(context(), :client_id, "other-client")
      ]

      for caller <- mismatches do
        next = Map.update!(first, :assigns, &Map.put(&1, :attesto_context, caller))

        assert_raise SessionOwnerMismatchError, fn ->
          AttestoMCP.Anubis.put_auth(next)
        end
      end
    end

    test "compares an owner restored with string keys" do
      owner = %{
        "iss" => "https://issuer.example",
        "sub" => "oc_user-123",
        "client_id" => "client-abc"
      }

      frame = frame_with(%{"attesto_context" => context(), "attesto_mcp_session_owner" => owner})

      assert AttestoMCP.Anubis.put_auth(frame).context.auth.sub == "oc_user-123"
    end

    test "fails closed when the verified context has no subject or OAuth client" do
      ctx =
        context()
        |> Map.put(:subject, nil)
        |> Map.put(:client_id, nil)
        |> Map.update!(:claims, &Map.drop(&1, ["sub", "client_id"]))

      assert_raise SessionOwnerMismatchError, ~r/neither a subject nor an OAuth client/, fn ->
        frame_with(%{attesto_context: ctx}) |> AttestoMCP.Anubis.put_auth()
      end
    end

    test "tolerates a context with no raw claims (aud/exp/iat nil, raw_claims empty)" do
      ctx = %{context() | claims: nil}
      frame = frame_with(%{attesto_context: ctx})

      auth = AttestoMCP.Anubis.put_auth(frame).context.auth
      assert auth.aud == nil
      assert auth.exp == nil
      assert auth.iat == nil
      assert auth.raw_claims == %{}
      # The non-claims-derived fields still project.
      assert auth.sub == "oc_user-123"
      assert auth.scopes == ["tools:read", "tools:write"]
    end
  end

  describe "compile guard" do
    test "the bridge is defined iff Anubis.Server.Frame is available" do
      # The module exists only because the `if Code.ensure_loaded?/1` guard on
      # `Anubis.Server.Frame` held. A host without anubis_mcp has neither module,
      # so attesto_mcp compiles and runs with Anubis absent.
      assert Code.ensure_loaded?(AttestoMCP.Anubis) == Code.ensure_loaded?(Frame)
    end
  end
end
