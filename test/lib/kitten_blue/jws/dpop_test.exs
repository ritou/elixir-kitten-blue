defmodule KittenBlue.JWS.DPoPTest do
  use ExUnit.Case

  alias KittenBlue.{JWS.DPoP, JWK}
  doctest DPoP

  test "generate_jwk" do
    assert {:ok, jwk = %JWK{}} = DPoP.generate_private_key()
    assert jwk.alg == "ES256"
    assert jwk.key

    assert {:ok, jwk = %JWK{}} = DPoP.generate_private_key(alg: "ES256")
    assert jwk.alg == "ES256"
    assert jwk.key

    assert {:ok, jwk = %JWK{}} = DPoP.generate_private_key(alg: "RS256")
    assert jwk.alg == "RS256"
    assert jwk.key
  end

  test "issue_and_verify" do
    assert {:ok, jwk = %JWK{}} = DPoP.generate_private_key()

    payload = %{
      "jti" => "-BwC3ESc6acc2lTc",
      "htm" => "POST",
      "htu" => "https://server.example.com/token",
      "iat" => 1_562_262_616
    }

    assert {:ok, jwt} = DPoP.issue_dpop_proof_jwt(payload, jwk)
    assert {:ok, jwt_header} = JOSE.JWS.peek_protected(jwt) |> Jason.decode()
    assert {:ok, jwt_payload} = JOSE.JWS.peek_payload(jwt) |> Jason.decode()

    assert %{
             "alg" => "ES256",
             "typ" => "dpop+jwt",
             "jwk" => %{
               "crv" => "P-256",
               "kty" => "EC",
               "x" => _,
               "y" => _
             }
           } = jwt_header

    assert payload == jwt_payload
  end
end
