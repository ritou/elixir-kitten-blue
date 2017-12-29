defmodule KittenBlue.JWK do
  @moduledoc """
  Structure containing `kid`, `alg`, `JOSE.JWK` and handling functions
  """

  defstruct [
    :kid,
    :alg,
    :key
  ]
  
  @type t :: %__MODULE__{kid: String.t, alg: String.t, key: JOSE.JWK.t}

  def new(opts) do
    struct(__MODULE__, Map.new(opts))
  end
end
