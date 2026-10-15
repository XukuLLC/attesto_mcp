defmodule AttestoMCP.Test.ValidJasonStruct do
  @moduledoc false
  @derive Jason.Encoder
  defstruct [:name, :count]
end

defmodule AttestoMCP.Test.InvalidNestedJasonStruct do
  @moduledoc false
  @derive Jason.Encoder
  defstruct [:value]
end
