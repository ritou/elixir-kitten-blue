defmodule KittenBlue.SD.Disclosure do
  @moduledoc """
  A module that represents the "Disclosure" defined in the SD-JWT specification.

  Selective Disclosure for JWTs (SD-JWT)
  https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-03.html

  TODO: more description

  A class that represents the "Disclosure" defined in the SD-JWT specification.
  https://github.com/authlete/sd-jwt
  """

  defstruct salt: :crypto.strong_rand_bytes(16) |> Base.url_encode64(padding: false),
            claim_name: "",
            claim_value: nil,
            json: "",
            disclosure: "",
            default_digest: "",
            hash_code: 0

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
  def new(claim_name, claim_value, salt \\ nil) when is_nil(claim_name) or is_nil(claim_value) do
    raise ArgumentError, "claim_name and claim_value cannot be nil"
  end

  def new(claim_name, claim_value, salt \\ nil) do
    %__MODULE__{salt: salt, claim_name: claim_name, claim_value: claim_value}
    |> generate_json()
    |> generate_disclosure()
  end

  # private

  defp generate_json(%{salt: salt, claim_name: claim_name, claim_value: claim_value} = disclosure) do
    json = [salt, claim_name, claim_value] |> Jason.encode!()
    Map.update!(disclosure, :json, &json/0)
  end

  defp generate_disclosure(%{json: json} = disclosure) do
    disclosure_byte_array = json |> String.to_charlist() |> :unicode.characters_to_binary()
    Map.update!(disclosure, :disclosure, &disclosure_byte_array/0)
  end
end
