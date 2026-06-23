defmodule AttestoMCP.Anubis.JSONSafe do
  @moduledoc """
  Produce a JSON-safe copy of an MCP session-state map before it is written to a
  `jsonb` column.

  Anubis folds the whole request `conn.assigns` into the persisted session
  `frame`, so the state map an `Anubis.Server.Session.Store` is handed can carry
  values with **no `JSON.Encoder` implementation** - a request-scoped struct
  (e.g. a host's authenticated-user struct), a tuple, a pid, a ref, a function,
  a `MapSet`. Encoding such a map raises in the database driver, which - because
  it happens mid-`initialize` - would crash the session process and drop the
  connection.

  `sanitize/1` recursively drops anything non-encodable from its enclosing map
  or list while preserving encodable siblings:

    * a struct **with** a `JSON.Encoder` impl (`DateTime`, `Date`, `Decimal`,
      ...) is kept; a bare struct without one is dropped;
    * a map keeps only entries whose key is a valid JSON object key (binary or
      atom) **and** whose value survives sanitization;
    * a list keeps only its surviving elements.

  Keys are otherwise preserved as-is, so a string-keyed restore reads the same
  values back after the `jsonb` round-trip. The result always encodes cleanly.
  """

  # Out-of-band drop sentinel. A two-element module tuple is itself never a kept
  # (JSON-safe) value, so it cannot collide with a legitimate sanitized value the
  # way a bare atom sentinel could (a real `:__drop__` in the input would then be
  # wrongly filtered).
  @drop {__MODULE__, :__drop__}

  @doc """
  Return a JSON-encodable copy of `value`, dropping any non-encodable members.

  A top-level value that is itself non-encodable (and not a map or list to
  descend into) sanitizes to an empty map, so the return is always encodable.
  """
  @spec sanitize(term()) :: term()
  def sanitize(value) do
    case safe(value) do
      @drop -> %{}
      sanitized -> sanitized
    end
  end

  defp safe(%_{} = struct) do
    if encodable?(struct), do: struct, else: @drop
  end

  defp safe(map) when is_map(map) do
    Map.new(for {k, v} <- map, json_key?(k), (sv = safe(v)) != @drop, do: {k, sv})
  end

  # A non-empty keyword list cannot be encoded as a JSON value (it is a list of
  # tuples), but it carries data the caller meant to keep. Convert it to an
  # object rather than silently collapsing every entry to `[]`. An empty list is
  # a valid JSON array and stays one.
  defp safe(list) when is_list(list) and list != [] do
    if Keyword.keyword?(list), do: safe(Map.new(list)), else: sanitize_list(list)
  end

  defp safe(list) when is_list(list), do: list

  # A binary is kept only when it is valid UTF-8: `is_binary/1` admits arbitrary
  # byte sequences, but the JSON encoder rejects invalid UTF-8 and would raise on
  # the insert. A non-byte-aligned bitstring is never JSON-encodable, so drop it.
  defp safe(value) when is_binary(value) do
    if String.valid?(value), do: value, else: @drop
  end

  defp safe(value) when is_bitstring(value), do: @drop

  defp safe(value) do
    if encodable?(value), do: value, else: @drop
  end

  defp sanitize_list(list), do: for(v <- list, (sv = safe(v)) != @drop, do: sv)

  # A binary key is kept only when it is valid UTF-8 (see `safe/1` for binaries);
  # an atom key encodes to its name. Any other key (integer, tuple, ...) cannot
  # be a JSON object key and its entry is dropped.
  defp json_key?(key) when is_atom(key), do: true
  defp json_key?(key) when is_binary(key), do: String.valid?(key)
  defp json_key?(_key), do: false

  defp encodable?(value), do: not is_nil(JSON.Encoder.impl_for(value))
end
