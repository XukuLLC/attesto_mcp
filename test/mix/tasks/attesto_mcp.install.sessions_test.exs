defmodule Mix.Tasks.AttestoMcp.Install.SessionsTest do
  # Module name mirrors the task module Mix resolves; see the note on
  # Mix.Tasks.AttestoMcp.Install.Sessions.
  use ExUnit.Case, async: true

  import Igniter.Test

  describe "mix attesto_mcp.install.sessions" do
    test "configures the Ecto session store with the host repo" do
      config =
        phx_test_project()
        |> Igniter.compose_task("attesto_mcp.install.sessions", ["--repo", "Test.Repo"])
        |> apply_igniter!()
        |> config_source()

      assert config =~ ":anubis_mcp"
      assert config =~ "session_store"
      assert config =~ "AttestoMCP.Anubis.SessionStore.Ecto"
      assert config =~ "Test.Repo"
      assert config =~ "enabled: true"
    end

    test "--registry adds the horde dependency" do
      mix =
        phx_test_project()
        |> Igniter.compose_task("attesto_mcp.install.sessions", ["--repo", "Test.Repo", "--registry"])
        |> apply_igniter!()
        |> source("mix.exs")

      assert mix =~ ":horde"
    end

    test "without --registry, horde is not added" do
      mix =
        phx_test_project()
        |> Igniter.compose_task("attesto_mcp.install.sessions", ["--repo", "Test.Repo"])
        |> apply_igniter!()
        |> source("mix.exs")

      refute mix =~ ":horde"
    end

    test "is idempotent across re-runs" do
      installed =
        phx_test_project()
        |> Igniter.compose_task("attesto_mcp.install.sessions", ["--repo", "Test.Repo"])
        |> apply_igniter!()

      # Re-run on the already-installed project: the config key is updated in
      # place, never duplicated, so a second apply changes nothing.
      rerun =
        installed
        |> Igniter.compose_task("attesto_mcp.install.sessions", ["--repo", "Test.Repo"])
        |> apply_igniter!()

      assert config_source(rerun) == config_source(installed)
    end
  end

  defp config_source(igniter), do: source(igniter, "config/config.exs")

  defp source(igniter, path) do
    igniter.rewrite
    |> Rewrite.source!(path)
    |> Rewrite.Source.get(:content)
  end
end
