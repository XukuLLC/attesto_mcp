# Store tests are tagged `:ecto` and excluded by default; they run only when a
# SQL backend is available (`mix test --include ecto`). The database is
# provisioned only when those tests are included, so the default run needs no
# running SQL server.

alias AttestoMCP.TestRepo
alias AttestoMCP.TestRepo.Migrations.CreateSessions

ExUnit.configure(exclude: [:ecto])

ecto_included? =
  ExUnit.configuration()
  |> Keyword.get(:include, [])
  |> Enum.any?(&(&1 == :ecto or match?({:ecto, _}, &1)))

if ecto_included? do
  Application.put_env(:attesto_mcp, TestRepo,
    username: System.get_env("POSTGRES_USER", "postgres"),
    password: System.get_env("POSTGRES_PASSWORD", "postgres"),
    hostname: System.get_env("POSTGRES_HOST", "localhost"),
    database: System.get_env("POSTGRES_DB", "attesto_mcp_test"),
    pool: Ecto.Adapters.SQL.Sandbox,
    pool_size: 10
  )

  {:ok, _} = Application.ensure_all_started(:ecto_sql)
  {:ok, _} = Application.ensure_all_started(:postgrex)

  _ = TestRepo.__adapter__().storage_up(TestRepo.config())

  {:ok, _pid} = TestRepo.start_link()

  # Point the store's runtime repo resolution at the test repo.
  Application.put_env(:attesto_mcp, :repo, TestRepo)

  Ecto.Migrator.run(TestRepo, [{0, CreateSessions}], :up,
    all: true,
    log: false
  )

  Ecto.Adapters.SQL.Sandbox.mode(TestRepo, :manual)
end

ExUnit.start()
