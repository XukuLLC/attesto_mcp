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
    `Anubis.Server.Context.auth_claims/0` shape.

    The projection is purely mechanical. It carries no application policy - no
    scope-superset/admin expansion, no role mapping, no tenant or audit logic,
    no "which tools are visible" rules. Those belong in the host app; this only
    surfaces the verified claims in the place Anubis reads them.

    ## Host wiring

    Call it once at the top of the server's `handle_request/2` (or any callback
    that needs the identity):

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

    @doc """
    Project the verified `:attesto_context` into `frame.context.auth`.

    Idempotent and non-destructive:

      * if `frame.context.auth` is already set, the frame is returned unchanged
        (a host or an earlier call owns it);
      * if `frame.assigns[:attesto_context]` is absent (unauthenticated request,
        STDIO transport, or the auth plug did not run), the frame is returned
        unchanged.

    Otherwise `frame.context.auth` is set to the `Anubis.Server.Context`
    auth-claims map projected from the context.
    """
    @spec put_auth(Frame.t()) :: Frame.t()
    def put_auth(%Frame{context: %{auth: auth}} = frame) when not is_nil(auth), do: frame

    def put_auth(%Frame{assigns: assigns, context: context} = frame) do
      case Map.get(assigns, @context_key) do
        ctx when is_map(ctx) -> %{frame | context: %{context | auth: auth_claims(ctx)}}
        _ -> frame
      end
    end

    # Mechanical projection of the attesto context map onto Anubis's documented
    # `auth_claims/0` shape. `scope` is the space-delimited string and `scopes`
    # is the list form of the SAME granted set; `aud`/`exp`/`iat` are read from
    # the raw verified claims so the full Anubis contract is populated.
    defp auth_claims(ctx) do
      claims = as_map(Map.get(ctx, :claims))
      scopes = scope_list(Map.get(ctx, :scope))

      %{
        sub: Map.get(ctx, :subject),
        aud: Map.get(claims, "aud"),
        scope: Enum.join(scopes, " "),
        scopes: scopes,
        exp: Map.get(claims, "exp"),
        iat: Map.get(claims, "iat"),
        client_id: Map.get(ctx, :client_id),
        raw_claims: claims
      }
    end

    defp scope_list(scopes) when is_list(scopes), do: scopes
    defp scope_list(scope) when is_binary(scope), do: String.split(scope, ~r/\s+/, trim: true)
    defp scope_list(_), do: []

    defp as_map(claims) when is_map(claims), do: claims
    defp as_map(_), do: %{}
  end
end
