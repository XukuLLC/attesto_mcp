if Code.ensure_loaded?(Ecto.Schema) do
  defmodule AttestoMCP.Anubis.Session do
    @moduledoc """
    Persisted Anubis MCP session state, backing `AttestoMCP.Anubis.SessionStore.Ecto`.

    One row per MCP session, keyed by the client's `Mcp-Session-Id`. `state` is
    the JSON-serializable session map Anubis produces (client_info, capabilities,
    `frame`, ...), stored as `jsonb` so it round-trips with string keys.
    `expires_at` bounds how long a disconnected session may be restored; expired
    rows are reaped lazily on load and by the store's `cleanup_expired/1`.

    Compile-guarded on `Ecto.Schema`: a consumer that does not persist MCP
    sessions never compiles it.
    """

    use Ecto.Schema

    import Ecto.Changeset

    @type t :: %__MODULE__{}

    @primary_key {:session_id, :string, autogenerate: false}
    schema "attesto_mcp_sessions" do
      field(:state, :map, default: %{})
      field(:expires_at, :utc_datetime_usec)

      timestamps(type: :utc_datetime_usec)
    end

    @fields ~w(session_id state expires_at)a

    @doc """
    Build the upsert changeset for a session row. Fail-closed: the `session_id`
    and `expires_at` are required.
    """
    @spec changeset(t() | Ecto.Changeset.t(), map()) :: Ecto.Changeset.t()
    def changeset(session, attrs) do
      session
      |> cast(attrs, @fields)
      |> validate_required([:session_id, :expires_at])
      |> unique_constraint(:session_id, name: :attesto_mcp_sessions_pkey)
    end
  end
end
