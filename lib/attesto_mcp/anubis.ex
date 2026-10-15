if Code.ensure_loaded?(Anubis.Server.Frame) do
  defmodule AttestoMCP.Anubis do
    @moduledoc """
    Bridge a verified resource-server identity into the Anubis MCP frame.

    `AttestoMCP.Plug.Authenticate` (or `AttestoPhoenix.Plug.Authenticate`)
    verifies the access token and assigns a protocol-shaped context onto the
    conn under `:attesto_context`. The Anubis HTTP transport copies
    `conn.assigns` into `frame.assigns`, so that context is reachable as
    `frame.assigns[:attesto_context]` inside the server.

    Anubis's own authorization machinery - the `tools/list` visibility filter,
    `Frame.scopes/1`, `Frame.has_scope?/2`, any per-tool scope gate - reads the
    identity from `frame.context.auth` (an `Anubis.Server.Context` field), which
    is `nil` until a host populates it. `put_auth/1` performs that one
    projection: `frame.assigns[:attesto_context]` -> `frame.context.auth`, in the
    auth-claims map shape `Anubis.Server.Context` documents.

    The bridge does not add application authorization policy such as role,
    tenant, or tool-visibility rules. It records the first verified issuer,
    subject, and OAuth client that reaches a host callback and rejects a
    different identity on a later callback in the same live session.

    ## Host wiring

    Call it in `init/2` so initialization records the owner, then at the top of
    every request callback that uses the identity or session state:

        def init(_client_info, frame) do
          {:ok, AttestoMCP.Anubis.put_auth(frame)}
        end

        def handle_request(request, frame) do
          frame = AttestoMCP.Anubis.put_auth(frame)
          # ... Anubis authorization now sees the verified identity ...
        end

    The module is compile-guarded on `Anubis.Server.Frame`: a resource server
    that does not depend on `anubis_mcp` never compiles it (mirroring how
    attesto core gates its optional `Plug` surface on `Plug.Conn`).
    """

    alias Anubis.Server.Frame

    # The conn/frame assign key `AttestoPhoenix.Plug.Authenticate` writes the
    # verified context under (`AttestoMCP.Plug.Authenticate` assigns the same
    # protocol-shaped map). Kept in sync with that plug's `:context_key` default.
    @context_key :attesto_context
    @session_owner_key :attesto_mcp_session_owner

    defmodule SessionOwnerMismatchError do
      @moduledoc "Raised when an authenticated caller addresses another identity's MCP session."
      defexception message: "MCP session owner does not match the authenticated caller"
    end

    @doc """
    Project the verified `:attesto_context` into `frame.context.auth`.

    Idempotent and non-destructive:

      * if `frame.context.auth` is already set, that value is never overwritten
        (a host or an earlier call owns it), while the verified context is still
        checked against the session owner;
      * if `frame.assigns[:attesto_context]` is absent (unauthenticated request,
        STDIO transport, or the auth plug did not run), the frame is returned
        unchanged.

    Otherwise `frame.context.auth` is set to the `Anubis.Server.Context`
    auth-claims map projected from the context.

    The first verified context also records a session-owner marker as described by
    `put_auth/2`.
    """
    @spec put_auth(Frame.t()) :: Frame.t()
    def put_auth(%Frame{} = frame), do: put_auth(frame, [])

    @doc """
    Project a verified context using an optional custom assign key.

    `:context_key` must be an atom and defaults to `:attesto_context`, matching
    `AttestoMCP.Plug.Authenticate`. Both the atom key used by live HTTP requests
    and its string form produced by a JSON session-store round-trip are read.

    The first verified identity seen by a host callback is recorded in the live
    frame. A later callback carrying a different issuer, subject, or OAuth client
    raises `SessionOwnerMismatchError`. Anubis reports that exception as a failed
    request or session rather than an OAuth 401/403. Anubis handles initialization,
    GET/SSE, DELETE, and persisted-session recovery before callbacks, and its 2.0
    HTTP recovery path does not restore saved frame assigns. This guard therefore
    protects only callback-visible state in the same live session. Hosts requiring
    complete session isolation should use `attesto_mcp_server`.
    """
    @spec put_auth(Frame.t(), keyword()) :: Frame.t()
    def put_auth(%Frame{assigns: assigns, context: context} = frame, opts) when is_list(opts) do
      context_key = Keyword.get(opts, :context_key, @context_key)

      if !is_atom(context_key) do
        raise ArgumentError, ":context_key must be an atom"
      end

      case fetch_assign(assigns, context_key) do
        ctx when is_map(ctx) ->
          frame = bind_session_owner!(frame, ctx)

          if is_nil(context.auth) do
            %{frame | context: %{context | auth: auth_claims(ctx)}}
          else
            frame
          end

        _ ->
          frame
      end
    end

    # Mechanical projection of the attesto context map onto Anubis's documented
    # `auth_claims/0` shape. `scope` is the space-delimited string and `scopes`
    # is the list form of the SAME granted set; `aud`/`exp`/`iat` are read from
    # the raw verified claims so the full Anubis contract is populated.
    defp auth_claims(ctx) do
      claims = as_map(fetch(ctx, :claims))
      scopes = scope_list(fetch(ctx, :scope))

      %{
        sub: fetch(ctx, :subject),
        aud: fetch(claims, :aud),
        scope: Enum.join(scopes, " "),
        scopes: scopes,
        exp: fetch(claims, :exp),
        iat: fetch(claims, :iat),
        client_id: fetch(ctx, :client_id),
        raw_claims: claims
      }
    end

    defp bind_session_owner!(%Frame{assigns: assigns} = frame, ctx) do
      owner = session_owner!(ctx)

      case fetch_assign(assigns, @session_owner_key) do
        nil ->
          %{frame | assigns: Map.put(assigns, @session_owner_key, owner)}

        existing when is_map(existing) ->
          if normalize_owner(existing) == owner do
            frame
          else
            raise SessionOwnerMismatchError
          end

        _ ->
          raise SessionOwnerMismatchError
      end
    end

    defp session_owner!(ctx) do
      claims = as_map(fetch(ctx, :claims))
      subject = fetch(ctx, :subject) || fetch(claims, :sub)
      client_id = fetch(ctx, :client_id) || fetch(claims, :client_id)

      if !(non_empty_binary?(subject) or non_empty_binary?(client_id)) do
        raise SessionOwnerMismatchError,
          message: "verified MCP identity has neither a subject nor an OAuth client identifier"
      end

      %{
        "iss" => fetch(claims, :iss),
        "sub" => subject,
        "client_id" => client_id
      }
    end

    defp normalize_owner(owner) do
      %{
        "iss" => fetch(owner, :iss),
        "sub" => fetch(owner, :sub),
        "client_id" => fetch(owner, :client_id)
      }
    end

    defp fetch_assign(assigns, key) do
      case Map.fetch(assigns, key) do
        {:ok, value} -> value
        :error -> Map.get(assigns, Atom.to_string(key))
      end
    end

    defp fetch(map, key) when is_map(map) and is_atom(key) do
      case Map.fetch(map, key) do
        {:ok, value} -> value
        :error -> Map.get(map, Atom.to_string(key))
      end
    end

    defp non_empty_binary?(value), do: is_binary(value) and value != ""

    defp scope_list(scopes) when is_list(scopes), do: scopes
    defp scope_list(scope) when is_binary(scope), do: String.split(scope, ~r/\s+/, trim: true)
    defp scope_list(_), do: []

    defp as_map(claims) when is_map(claims), do: claims
    defp as_map(_), do: %{}
  end
end
