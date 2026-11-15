if Code.ensure_loaded?(Phoenix.Controller) do
  defmodule AttestoMCP.MetadataController do
    @moduledoc """
    Phoenix controller that serves RFC 9728 protected-resource metadata.

    Routes mounted by `AttestoMCP.Router.attesto_mcp_protected_resource_metadata/2`
    dispatch here. The controller reads the resource path and metadata options
    placed in `conn.private` by the route, builds the document with
    `AttestoMCP.Metadata.protected_resource/3`, and renders it as JSON. The
    `resource` identifier comes from `AttestoMCP.Metadata.resolve_origin/2`.
    The authorization server must be supplied by `:authorization_servers`,
    `:issuer`, or `:config`; it is never derived from the request authority.

    This public discovery controller does not authenticate tokens or select an
    audience policy. Configure `:resource_audience` or `:trusted_audiences` on
    the plug protecting the MCP endpoint, even when this controller publishes
    its canonical resource identifier.

    Because the `resource` identifier is resolved the same way
    `AttestoMCP.Plug.ProtectResource` resolves its `WWW-Authenticate`
    `resource_metadata` challenge, the discovered metadata URL and the served
    `resource` value match - provided both call sites receive the same origin
    (with no pin they both derive from the request; behind a proxy pass the same
    `:base_url`/`:origin` to the router macro and the plug).

    A document with a static `:resource`, `:base_url`, or `:origin` string is
    served with `Cache-Control: public, max-age=3600`. A document built by an
    origin callback or derived from the request `Host` is served with
    `Cache-Control: no-store`.

    The controller compiles only when Phoenix is available; Plug-only consumers
    do not pull it in.
    """

    use Phoenix.Controller, formats: [:json]

    alias Attesto.Plug.ResourceMetadata

    @doc "Render the RFC 9728 metadata for this route's MCP resource."
    def show(conn, _params) do
      opts = Map.get(conn.private, :attesto_mcp_metadata_opts, [])
      path = Map.fetch!(conn.private, :attesto_mcp_resource_path)

      ResourceMetadata.call(
        conn,
        Keyword.merge(opts, resource_path: path, metadata: AttestoMCP.Metadata)
      )
    end
  end
end
