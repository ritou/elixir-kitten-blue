defmodule KittenBlue.JWS.DPoPTest do
  use ExUnit.Case

  alias KittenBlue.{JWS, JWS.DPoP, JWK}
  doctest DPoP

  test "RFC 9449" do
    # ref. https://datatracker.ietf.org/doc/html/rfc9449#section-4.1
    jwt =
      "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCRnMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JEQSIsImNydiI6IlAtMjU2In19.eyJqdGkiOiItQndDM0VTYzZhY2MybFRjIiwiaHRtIjoiUE9TVCIsImh0dSI6Imh0dHBzOi8vc2VydmVyLmV4YW1wbGUuY29tL3Rva2VuIiwiaWF0IjoxNTYyMjYyNjE2fQ.2-GxA6T8lP4vfrg8v-FdWP0A0zdrj8igiMLvqRMUvwnQg4PtFLbdLXiOSsX0x7NVY-FNyJK70nfbV37xRZT3Lg"

    assert {:ok, payload, header, _} = DPoP.verify_dpop_proof_jwt(jwt)

    assert %{
             "htm" => "POST",
             "htu" => "https://server.example.com/token",
             "iat" => 1_562_262_616,
             "jti" => "-BwC3ESc6acc2lTc"
           } = payload

    assert %{
             "alg" => "ES256",
             "jwk" => %{
               "crv" => "P-256",
               "kty" => "EC",
               "x" => "l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs",
               "y" => "9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA"
             },
             "typ" => "dpop+jwt"
           } = header

    # ref. https://datatracker.ietf.org/doc/html/rfc9449#section-7.1
    jwt =
      "eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7Imt0eSI6IkVDIiwieCI6Imw4dEZyaHgtMzR0VjNoUklDUkRZOXpDa0RscEJoRjQyVVFVZldWQVdCRnMiLCJ5IjoiOVZFNGpmX09rX282NHpiVFRsY3VOSmFqSG10NnY5VERWclUwQ2R2R1JEQSIsImNydiI6IlAtMjU2In19.eyJqdGkiOiJlMWozVl9iS2ljOC1MQUVCIiwiaHRtIjoiR0VUIiwiaHR1IjoiaHR0cHM6Ly9yZXNvdXJjZS5leGFtcGxlLm9yZy9wcm90ZWN0ZWRyZXNvdXJjZSIsImlhdCI6MTU2MjI2MjYxOCwiYXRoIjoiZlVIeU8ycjJaM0RaNTNFc05yV0JiMHhXWG9hTnk1OUlpS0NBcWtzbVFFbyJ9.2oW9RP35yRqzhrtNP86L-Ey71EOptxRimPPToA1plemAgR6pxHF8y6-yqyVnmcw6Fy1dqd-jfxSYoMxhAJpLjA"

    assert {:ok, payload, header, _} = DPoP.verify_dpop_proof_jwt(jwt)

    assert %{
             "htm" => "GET",
             "htu" => "https://resource.example.org/protectedresource",
             "iat" => 1_562_262_618,
             "jti" => "e1j3V_bKic8-LAEB",
             "ath" => "fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo"
           } = payload

    assert %{
             "alg" => "ES256",
             "jwk" => %{
               "crv" => "P-256",
               "kty" => "EC",
               "x" => "l8tFrhx-34tV3hRICRDY9zCkDlpBhF42UQUfWVAWBFs",
               "y" => "9VE4jf_Ok_o64zbTTlcuNJajHmt6v9TDVrU0CdvGRDA"
             },
             "typ" => "dpop+jwt"
           } = header
  end

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

  test "issue" do
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

    assert {:error, :invalid_payload} = DPoP.issue_dpop_proof_jwt(%{}, jwk)
  end

  test "verify" do
    assert {:error, :invalid_dpop_proof_jwt} = DPoP.verify_dpop_proof_jwt("invalid")

    assert {:ok, jwk = %JWK{}} = DPoP.generate_private_key()

    payload = %{
      "jti" => "-BwC3ESc6acc2lTc",
      "htm" => "POST",
      "htu" => "https://server.example.com/token",
      "iat" => 1_562_262_616
    }

    assert {:ok, jwt} = DPoP.issue_dpop_proof_jwt(payload, jwk)

    assert {:ok, payload, header, decode_jwk} = DPoP.verify_dpop_proof_jwt(jwt)

    assert JWK.to_thumbprint(jwk) == JWK.to_thumbprint(decode_jwk)

    assert %{
             "htm" => "POST",
             "htu" => "https://server.example.com/token",
             "iat" => 1_562_262_616,
             "jti" => "-BwC3ESc6acc2lTc"
           } = payload

    assert %{
             "alg" => "ES256",
             "jwk" => %{
               "crv" => "P-256",
               "kty" => "EC",
               "x" => _,
               "y" => _
             },
             "typ" => "dpop+jwt"
           } = header

    assert {:error, :invalid_jwt_signature} = DPoP.verify_dpop_proof_jwt(jwt <> "invalid")

    # empty payload
    {:ok, jwt} = JWS.sign(%{}, jwk, header, ignore_kid: true)

    assert {:error, :invalid_payload} = DPoP.verify_dpop_proof_jwt(jwt)

    # pubkey not found
    {:ok, jwt} = JWS.sign(payload, jwk, %{})

    assert {:error, :invalid_header} = DPoP.verify_dpop_proof_jwt(jwt)
  end
end
