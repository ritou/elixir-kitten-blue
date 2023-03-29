defmodule KittenBlue.SD.Disclosure do
  @moduledoc """
  A module that represents the "Disclosure" defined in the SD-JWT specification.

  Selective Disclosure for JWTs (SD-JWT)
  https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-03.html

  TODO: more description

  A class that represents the "Disclosure" defined in the SD-JWT specification.
  https://github.com/authlete/sd-jwt
  """

  defstruct [
    :salt,
    :claim_name,
    :claim_value,
    :json,
    :disclosure,
    :default_digest,
    :hash_code
  ]

  @type t :: %__MODULE__{
          salt: String.t(),
          claim_name: String.t(),
          claim_value: any(),
          json: String.t(),
          disclosure: String.t(),
          default_digest: String.t(),
          hash_code: integer()
        }

  @doc """
  Constructor with a pair of claim name and claim value. A salt is randomly generated.
  """
  @spec new(claim_name :: String.t(), claim_value: any(), salt: String.t() | nil) :: t()
  def new(claim_name, claim_value, salt \\ nil)
  def new(claim_name, claim_value, salt) when not is_nil(claim_name) and not is_nil(claim_value) do
    salt = salt || generate_salt()

    %__MODULE__{salt: salt, claim_name: claim_name, claim_value: claim_value}
    |> generate_json()
    |> generate_disclosure()
  end

  # TODO: consider the error format
  def new(_, _, _), do: raise(ArgumentError)

  # private

  defp generate_json(
         disclosure = %__MODULE__{salt: salt, claim_name: claim_name, claim_value: claim_value}
       ) do
    json = [salt, claim_name, claim_value] |> Jason.encode!()
    Map.put(disclosure, :json, json)
  end

  defp generate_disclosure(disclosure = %__MODULE__{json: json}) do
    disclosure_byte_array = json |> String.to_charlist() |> :unicode.characters_to_binary()
    Map.put(disclosure, :disclosure, disclosure_byte_array)
  end

  defp generate_salt(), do: :crypto.strong_rand_bytes(16) |> Base.url_encode64(padding: false)
end
