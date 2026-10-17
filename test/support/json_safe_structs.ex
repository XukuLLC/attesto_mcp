defmodule AttestoMCP.Test.BareStruct do
  @moduledoc false
  defstruct [:x]
end

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
