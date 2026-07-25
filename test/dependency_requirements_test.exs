defmodule AttestoMCP.DependencyRequirementsTest do
  @moduledoc false
  use ExUnit.Case, async: true

  test "Plug admits every supported fixed branch and rejects affected predecessors" do
    requirement = requirement!(:plug)

    assert_matches(requirement, ~w(1.16.6 1.17.4 1.18.5 1.19.5 1.20.3 1.99.0))
    refute_matches(requirement, ~w(1.16.5 1.17.3 1.18.4 1.19.4 1.20.2 2.0.0))
  end

  test "optional integrations retain their tested floors and next-major caps" do
    assert_matches(requirement!(:phoenix), ~w(1.7.24 1.8.9 1.99.0))
    refute_matches(requirement!(:phoenix), ~w(1.7.23 1.8.8 2.0.0))

    assert_matches(requirement!(:igniter), ~w(0.6.0 0.99.0))
    refute_matches(requirement!(:igniter), ~w(0.5.99 1.0.0))

    assert_matches(requirement!(:anubis_mcp), ~w(1.7.0 1.99.0))
    refute_matches(requirement!(:anubis_mcp), ~w(1.6.99 2.0.0))
  end

  test "Attesto and test-only Postgrex use their patched floors" do
    case dependency!(:attesto) do
      {:attesto, requirement} when is_binary(requirement) ->
        assert_matches(requirement, ~w(1.3.0 1.99.0))
        refute_matches(requirement, ~w(1.2.5 2.0.0))

      {:attesto, opts} when is_list(opts) ->
        assert opts[:path], "expected the explicit ATTESTO_PATH development dependency"
    end

    assert_matches(requirement!(:postgrex), ~w(0.22.3 0.99.0))
    refute_matches(requirement!(:postgrex), ~w(0.22.2 1.0.0))
  end

  defp assert_matches(requirement, versions) do
    for version <- versions do
      assert Version.match?(version, requirement),
             "expected #{inspect(requirement)} to admit #{version}"
    end
  end

  defp refute_matches(requirement, versions) do
    for version <- versions do
      refute Version.match?(version, requirement),
             "expected #{inspect(requirement)} to reject #{version}"
    end
  end

  defp requirement!(app) do
    case dependency!(app) do
      {^app, requirement} when is_binary(requirement) -> requirement
      {^app, requirement, _opts} when is_binary(requirement) -> requirement
    end
  end

  defp dependency!(app) do
    AttestoMCP.MixProject.project()
    |> Keyword.fetch!(:deps)
    |> Enum.find(&(elem(&1, 0) == app))
  end
end
