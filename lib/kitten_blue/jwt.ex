defmodule KittenBlue.JWT do
  @moduledoc """
  This module provides JWT Claims handling functions.

  * verify_claims : Verify claims in Payload
  """

  @doc """
  Claims verification in Payload

  This function validates the basic claims defined in RFC7519.

  ```
  valid_claims = %{iss: "https://accounts.google.com", aud: "your_oidc_client_id", nonce: "12345"}

  :ok = KittenBlue.JWT.verify_claims(payload, valid_claims)
  ```

  This function supports the following claims

  * `iss` : Check for an exact match.
  * `aud` : Check for an exact match or list
  * `exp` : Is greater than specified value
  * `nbf` : Is less than the specified value

  """
  @spec verify_claims(payload :: map, valid_claims :: map) ::
          :ok | {:error, :invalid_payload, claim_name :: String.t()}
  def verify_claims(payload, valid_claims) when is_map(payload) and is_map(valid_claims) do
    with :ok <- validate_iss(payload["iss"], valid_claims["iss"]),
         :ok <- validate_aud(payload["aud"], valid_claims["aud"]),
         :ok <- validate_exp(payload["exp"], valid_claims["exp"]),
         :ok <- validate_nbf(payload["nbf"], valid_claims["nbf"]) do
      :ok
    end
  end

  defp validate_iss(_, nil), do: :ok
  defp validate_iss(iss, valid_iss) when iss == valid_iss, do: :ok
  defp validate_iss(_, _), do: {:error, :invalid_payload, "iss"}

  defp validate_aud(_, nil), do: :ok

  defp validate_aud(aud, valid_aud) when is_list(aud) do
    if valid_aud in aud do
      :ok
    else
      {:error, :invalid_payload, "aud"}
    end
  end

  defp validate_aud(aud, valid_aud) when aud == valid_aud, do: :ok
  defp validate_aud(_, _), do: {:error, :invalid_payload, "aud"}

  defp validate_exp(_, nil), do: :ok

  defp validate_exp(exp, valid_exp)
       when is_integer(exp) and is_integer(valid_exp) and exp >= valid_exp,
       do: :ok

  defp validate_exp(_, _), do: {:error, :invalid_payload, "exp"}

  defp validate_nbf(_, nil), do: :ok

  defp validate_nbf(nbf, valid_nbf)
       when is_integer(nbf) and is_integer(valid_nbf) and nbf <= valid_nbf,
       do: :ok

  defp validate_nbf(_, _), do: {:error, :invalid_payload, "nbf"}
end
