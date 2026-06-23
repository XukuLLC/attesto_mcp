defmodule AttestoMCP.TestRepo.Migrations.CreateSessions do
  @moduledoc false
  # Mirrors the table `mix attesto_mcp.gen.session_migration` generates, so the
  # store suite runs against the same schema a consumer installs.
  use Ecto.Migration

  def change do
    create table(:attesto_mcp_sessions, primary_key: false) do
      add(:session_id, :string, primary_key: true, null: false)
      add(:state, :map, null: false)
      add(:expires_at, :utc_datetime_usec, null: false)

      timestamps(type: :utc_datetime_usec)
    end

    create(index(:attesto_mcp_sessions, [:expires_at]))
  end
end
