defmodule KittenBlue.JWKTest do
  use ExUnit.Case

  alias KittenBlue.JWK
  doctest JWK

  @kid "sample2017"
  @alg "RS256"
  @key %{
    "kty" => "RSA",
    "n" => "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
    "e" => "AQAB",
    "d" => "X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q",
    "p" => "83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs",
    "q" => "3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk",
    "dp" => "G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0",
    "dq" => "s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk",
    "qi" => "GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU"
  } |> JOSE.JWK.from_map()

  test "RSA Private Key" do
    kb_jwk = [
      kid: @kid,
      alg: @alg,
      key: @key
    ] |> JWK.new()

    assert kb_jwk
    assert kb_jwk.kid == @kid
    assert kb_jwk.alg == @alg
    assert kb_jwk.key == @key
  end

  test "list_to_public_jwk_sets and public_jwk_sets_to_list" do
    kb_jwk = [
      kid: @kid,
      alg: @alg,
      key: @key
    ] |> JWK.new()

    jwk_list = [kb_jwk]
    public_jwk_sets = JWK.list_to_public_jwk_sets(jwk_list)

    assert public_jwk_sets["keys"]
    assert length(public_jwk_sets["keys"]) == 1
    for jwk <- public_jwk_sets["keys"] do
      assert jwk["kid"]
      assert jwk["alg"] == "RS256"
      assert jwk["kty"] == "RSA"
      assert jwk["e"]
      assert jwk["n"]
      assert !jwk["d"]
      assert !jwk["p"]
      assert !jwk["q"]
      assert !jwk["dp"]
      assert !jwk["dq"]
      assert !jwk["qi"]
    end
    public_jwk_list = JWK.public_jwk_sets_to_list(public_jwk_sets)
    assert length(public_jwk_list) == 1
    [public_jwk] = public_jwk_list
    assert public_jwk.kid == @kid
    assert public_jwk.alg == @alg
    assert public_jwk.key

    jwk_list = [nil, kb_jwk]
    assert public_jwk_sets == JWK.list_to_public_jwk_sets(jwk_list)

    assert [] == JWK.public_jwk_sets_to_list(%{})
    assert [] == JWK.public_jwk_sets_to_list(%{"keys" => ["invalid"]})
    # TODO : invalid JWK Sets
  end
end
