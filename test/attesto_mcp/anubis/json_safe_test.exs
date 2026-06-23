defmodule AttestoMCP.Anubis.JSONSafeTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias AttestoMCP.Anubis.JSONSafe

  defmodule BareStruct do
    @moduledoc false
    defstruct [:x]
  end

  # The result must always be encodable — that is the whole point.
  defp assert_encodable(value) do
    sanitized = JSONSafe.sanitize(value)
    assert is_binary(JSON.encode!(sanitized))
    sanitized
  end

  test "keeps an already-encodable map untouched" do
    map = %{"a" => 1, "b" => [1, 2, 3], "c" => %{"d" => "e"}}
    assert assert_encodable(map) == map
  end

  test "drops a bare struct value but keeps encodable siblings" do
    out = assert_encodable(%{"user" => %BareStruct{x: 1}, "keep" => "yes"})
    assert out == %{"keep" => "yes"}
  end

  test "keeps structs that DO have a JSON.Encoder impl (e.g. DateTime)" do
    dt = ~U[2026-06-23 00:00:00Z]
    out = assert_encodable(%{"at" => dt, "bad" => self()})
    assert out["at"] == dt
    refute Map.has_key?(out, "bad")
  end

  test "drops non-encodable scalars (pid, ref, tuple, function)" do
    out =
      assert_encodable(%{
        "pid" => self(),
        "ref" => make_ref(),
        "tuple" => {:a, :b},
        "fun" => fn -> :x end,
        "ok" => 1
      })

    assert out == %{"ok" => 1}
  end

  test "recurses into lists, dropping non-encodable elements" do
    out = assert_encodable(%{"xs" => [1, self(), 2, {:t}, 3]})
    assert out == %{"xs" => [1, 2, 3]}
  end

  test "drops map entries whose key is not a valid JSON object key" do
    out = assert_encodable(%{{:tuple, :key} => "v", "ok" => "v"})
    assert out == %{"ok" => "v"}
  end

  test "preserves nested encodable structure while pruning deep non-encodable values" do
    out =
      assert_encodable(%{
        "frame" => %{
          "assigns" => %{"mcp_user" => %BareStruct{x: 1}, "locale" => "en"},
          "list" => [%{"keep" => 1, "drop" => self()}]
        }
      })

    assert out == %{
             "frame" => %{
               "assigns" => %{"locale" => "en"},
               "list" => [%{"keep" => 1}]
             }
           }
  end

  test "a non-encodable top-level value sanitizes to an empty map (always encodable)" do
    assert JSONSafe.sanitize(self()) == %{}
    assert JSON.encode!(JSONSafe.sanitize(self())) == "{}"
  end

  test "drops invalid-UTF-8 binary values and keys (the encoder would raise)" do
    bad = <<0xFF, 0xFE>>
    out = assert_encodable(%{"ok" => "v", "bad" => bad, bad => "x"})
    assert out == %{"ok" => "v"}
  end

  test "drops a non-byte-aligned bitstring" do
    out = assert_encodable(%{"bits" => <<1::3>>, "ok" => 1})
    assert out == %{"ok" => 1}
  end

  test "converts a non-empty keyword list to an object instead of collapsing to []" do
    out = assert_encodable(%{"opts" => [a: 1, b: 2]})
    assert out == %{"opts" => %{a: 1, b: 2}}
  end

  test "keeps an empty list as an array (not an object)" do
    assert JSONSafe.sanitize(%{"xs" => []}) == %{"xs" => []}
  end

  test "a charlist stays a JSON array of integers" do
    assert JSONSafe.sanitize(%{"cs" => ~c"abc"}) == %{"cs" => [97, 98, 99]}
  end
end
