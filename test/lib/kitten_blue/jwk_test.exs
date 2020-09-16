defmodule KittenBlue.JWKTest do
  use ExUnit.Case

  alias KittenBlue.JWK
  doctest JWK

  @kid "sample2017"
  @alg "RS256"
  @key_map %{
    "kty" => "RSA",
    "n" =>
      "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
    "e" => "AQAB",
    "d" =>
      "X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqijwp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBznbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFzme1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q",
    "p" =>
      "83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPVnwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqVWlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs",
    "q" =>
      "3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyumqjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgxkIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk",
    "dp" =>
      "G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oimYwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_NmtuYZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0",
    "dq" =>
      "s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUUvMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk",
    "qi" =>
      "GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzgUIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rxyR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU"
  }
  @key @key_map |> JOSE.JWK.from_map()

  test "RSA Private Key" do
    kb_jwk =
      [
        kid: @kid,
        alg: @alg,
        key: @key
      ]
      |> JWK.new()

    assert kb_jwk
    assert kb_jwk.kid == @kid
    assert kb_jwk.alg == @alg
    assert kb_jwk.key == @key

    assert kb_jwk ==
             %{
               kid: @kid,
               alg: @alg,
               key: @key
             }
             |> JWK.new()

    assert kb_jwk == [@kid, @alg, @key] |> JWK.new()
  end

  test "list_to_public_jwk_sets and public_jwk_sets_to_list" do
    kb_jwk =
      [
        kid: @kid,
        alg: @alg,
        key: @key
      ]
      |> JWK.new()

    jwk_list = [kb_jwk]
    public_jwk_sets = JWK.list_to_public_jwk_sets(jwk_list)

    assert public_jwk_sets["keys"]
    assert length(public_jwk_sets["keys"]) == 1

    for jwk <- public_jwk_sets["keys"] do
      assert jwk["kid"] == @kid
      assert jwk["alg"] == "RS256"
      assert jwk["kty"] == @key_map["kty"]
      assert jwk["e"] == @key_map["e"]
      assert jwk["n"] == @key_map["n"]
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

    invalid_jwk_sets = %{
      "keys" => [
        nil,
        "invalid",
        %{},
        %{"alg" => "RS256"},
        %{"kid" => "sample"},
        %{"kid" => "sample", "alg" => "RS256"},
        %{"kid" => "sample", "kty" => @key_map["kty"], "e" => @key_map["e"], "n" => @key_map["n"]}
      ]
    }

    assert [] == JWK.public_jwk_sets_to_list(invalid_jwk_sets)

    google_public_jwk_sets_20180105 = %{
      "keys" => [
        %{
          "kty" => "RSA",
          "alg" => "RS256",
          "use" => "sig",
          "kid" => "1db0175d1c5f45a9dda279fc91b67a138bc20555",
          "n" =>
            "pcdeuY_mJq2tz9WHT8bv_l0oFC8cf1sgq6w7klIRiaJB7fyR-TpC5tVXG_-sVVGG8CHXADAO7iHblvH3BdLoHXLCpSHilGPq-UK5NkLpPI3NmUZMQvZM5p1l9Op-VlR8pmPR9aQj55MGskHr5ue6rCIlg60ESYxt8uvH5i67IgRl--_Iu3bFXzH_ulMp9SpMtlwMRFJtYLPJrlw76JmEnelU2KGgyWiHN8j93AJQsn-rxHHUCaWeXgtjEv3BIJxUo80qY9I78A6BzDqnemgVPq6SeZjzJrHu1x9X_Nr0a2XDU60j_8k22HFN-2zsOBaQ4KlDBSJvy9Nsg0iSXgYgKw",
          "e" => "AQAB"
        },
        %{
          "kty" => "RSA",
          "alg" => "RS256",
          "use" => "sig",
          "kid" => "8b6adb0cacfff2e8699e5215fef09c0e8763b52e",
          "n" =>
            "nxreSDGnSS0XbJHztUseniDjU85Wjk5WdtlknPTVoMxWwrqsL-7YG342kC6vUmcqPbpPY9AADbWOV7U_CZxnwBBbG0dvvAqwsrhUx8xR5qejMkYiNDqY9ASRXuB6FTVLtnke9APXNiuOll_tZxQ1lN7rF0wWkR7jjagjsKoVEzKJPVqAX4MTqHu9VDAzCYqrSvBhgm0RhaJvDeJkiCbEZ14bmtIioEbiBccohjNyHtXLW-b935Kf37T88eQMPoqn9_wo4LZswtqB5RtkF613BGnWbZ-0TAaIyaQ3cyhXH1SfGpyTgT2q8CApOa7GCdvdr1n2QfmSla_IcyzN3Uv1SQ",
          "e" => "AQAB"
        },
        %{
          "kty" => "RSA",
          "alg" => "RS256",
          "use" => "sig",
          "kid" => "9565a4e07b7040161a4b4ecfbebb8324608434f7",
          "n" =>
            "ooPkpVNbH31-yPg7XWtbeIbhWYHPMtB0Mi3V497Y0yloLhtayxUKF1XbOEoyqcjepgBZjFczk3GpKMReYCjkJsCHPlA7-AaWPUoXuaD9CmoCmBjB_wMRnpruvYeosW7V61FZHISOYb6EFqW3BS-QFtIDhrU8XnHs0P-C_xlUhKROQ9qKCYd8c-NggwsxXfPu4nZvmYSj-3NFQTjj412fuSUgaaMptodYCGG7WrRg9CxZhZVHBnwcYZKmXt_dWLCQes4tQ8G817WsontKs4-49NaAJKQWIYVV7GqALpREDQeOAgb_V90Sinn_9BX_Z_fb116-1TEmmPm2B6dkw73DBQ",
          "e" => "AQAB"
        },
        %{
          "kty" => "RSA",
          "alg" => "RS256",
          "use" => "sig",
          "kid" => "9233bcb10da10449fe0a247dbb02df734608a3fb",
          "n" =>
            "xJ-KJnOlP-fUXzREJwkSEYQrcgzy0P_7ksEiAxMicUBVzMJXQ8gUXf6Ucr-bPsysXmn6_qJTAirxpXf3E2wHakL9qonL3aipl4YMjjAur-_XaTtYMf1Uolx4ZTtL7HBtdLqXrk3klUoVtsE5_ofVoOni0kNYcYI4pKtf_DPJzmct3oFnqL-Tm9ioSngWAzJLXkQO-Ovxhba_fGnLENy1A4Jo_uJJREEl4OOC5m8wZweP6ABLYcdYPJC6YaR_9NEkUDIZXo4yT3y9bBZ0jXAilnTAJFKsKvfsf-y5jPTBVzfluenCfUQ4nXzqeiTzu76AiSLYfMJClgCJMBOPBRUgoQ",
          "e" => "AQAB"
        }
      ]
    }

    google_public_jwk_list = JWK.public_jwk_sets_to_list(google_public_jwk_sets_20180105)
    assert length(google_public_jwk_list) == 4
  end

  test "HS256" do
    alg_hs256 = "HS256"
    kid_hs256 = "hs256_201804"
    key_hs256_oct = :crypto.strong_rand_bytes(32)
    key_hs256 = key_hs256_oct |> JOSE.JWK.from_oct()
    jwk_hs256 = JWK.new([kid_hs256, alg_hs256, key_hs256])

    # HS256 with oct
    hs_compact = JWK.to_compact(jwk_hs256)
    assert [kid_hs256, alg_hs256, key_hs256_oct |> Base.encode64(padding: false)] == hs_compact
    assert jwk_hs256 == JWK.from_compact(hs_compact)
    hs_compact_list = JWK.list_to_compact([jwk_hs256])

    assert [[kid_hs256, alg_hs256, key_hs256_oct |> Base.encode64(padding: false)]] ==
             hs_compact_list

    assert [jwk_hs256] == JWK.compact_to_list(hs_compact_list)

    # HS256 with map
    hs_compact_with_map = JWK.to_compact(jwk_hs256, use_map: true)

    assert [kid_hs256, alg_hs256, key_hs256 |> JOSE.JWK.to_map() |> elem(1)] ==
             hs_compact_with_map

    assert jwk_hs256 == JWK.from_compact(hs_compact_with_map)
    hs_compact_list_with_map = JWK.list_to_compact([jwk_hs256], use_map: true)

    assert [[kid_hs256, alg_hs256, key_hs256 |> JOSE.JWK.to_map() |> elem(1)]] ==
             hs_compact_list_with_map

    assert [jwk_hs256] == JWK.compact_to_list(hs_compact_list_with_map)
  end

  test "RS256" do
    alg_rs256 = "RS256"
    kid_rs256 = "rs256_201804"
    key_rs256 = JOSE.JWK.from_pem_file("sample_pem/rsa-2048.pem")
    jwk_rs256 = JWK.new([kid_rs256, alg_rs256, key_rs256])

    # RS256 with PEM
    rs_compact = JWK.to_compact(jwk_rs256)
    assert [kid_rs256, alg_rs256, key_rs256 |> JOSE.JWK.to_pem() |> elem(1)] == rs_compact
    assert jwk_rs256 == JWK.from_compact(rs_compact)
    rs_compact_list = JWK.list_to_compact([jwk_rs256])
    assert [[kid_rs256, alg_rs256, key_rs256 |> JOSE.JWK.to_pem() |> elem(1)]] == rs_compact_list
    assert [jwk_rs256] == JWK.compact_to_list(rs_compact_list)

    # RS256 with map
    rs_compact_with_map = JWK.to_compact(jwk_rs256, use_map: true)

    assert [kid_rs256, alg_rs256, key_rs256 |> JOSE.JWK.to_map() |> elem(1)] ==
             rs_compact_with_map

    assert jwk_rs256 == JWK.from_compact(rs_compact)
    rs_compact_list_with_map = JWK.list_to_compact([jwk_rs256], use_map: true)

    assert [[kid_rs256, alg_rs256, key_rs256 |> JOSE.JWK.to_map() |> elem(1)]] ==
             rs_compact_list_with_map

    assert [jwk_rs256] == JWK.compact_to_list(rs_compact_list_with_map)
  end

  test "ES256" do
    alg_es256 = "ES256"
    kid_es256 = "es256_201804"
    key_es256 = JOSE.JWK.from_pem_file("sample_pem/ec-secp256r1-alice.pem")
    jwk_es256 = JWK.new([kid_es256, alg_es256, key_es256])

    # ES256 with pem
    es_compact = JWK.to_compact(jwk_es256)
    assert [kid_es256, alg_es256, key_es256 |> JOSE.JWK.to_pem() |> elem(1)] == es_compact
    assert jwk_es256 == JWK.from_compact(es_compact)
    es_compact_list = JWK.list_to_compact([jwk_es256])
    assert [[kid_es256, alg_es256, key_es256 |> JOSE.JWK.to_pem() |> elem(1)]] == es_compact_list
    assert [jwk_es256] == JWK.compact_to_list(es_compact_list)

    # ES256 with map
    es_compact_with_map = JWK.to_compact(jwk_es256, use_map: true)

    assert [kid_es256, alg_es256, key_es256 |> JOSE.JWK.to_map() |> elem(1)] ==
             es_compact_with_map

    assert jwk_es256 == JWK.from_compact(es_compact_with_map)
    es_compact_list_with_map = JWK.list_to_compact([jwk_es256], use_map: true)

    assert [[kid_es256, alg_es256, key_es256 |> JOSE.JWK.to_map() |> elem(1)]] ==
             es_compact_list_with_map

    assert [jwk_es256] == JWK.compact_to_list(es_compact_list_with_map)
  end

  test "Ed25519" do
    alg = "Ed25519"
    kid = "Ed25519_202009"
    # ref. https://tools.ietf.org/html/rfc8037#appendix-A
    ed25519_priv_map = %{
      "kty" => "OKP",
      "crv" => "Ed25519",
      "d" => "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A",
      "x" => "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
    }

    key_ed25519 = JOSE.JWK.from_map(ed25519_priv_map)
    jwk_ed25519 = JWK.new([kid, alg, key_ed25519])

    # NOTE: JOSE.JWK.from_pem issue (ErlangError) Erlang error: :curve25519_unsupported
    JOSE.crypto_fallback(true)

    # Ed25519 with pem
    ed25519_compact = JWK.to_compact(jwk_ed25519)
    assert [kid, alg, key_ed25519 |> JOSE.JWK.to_pem() |> elem(1)] == ed25519_compact
    assert jwk_ed25519 == JWK.from_compact(ed25519_compact)
    ed25519_compact_list = JWK.list_to_compact([jwk_ed25519])
    assert [[kid, alg, key_ed25519 |> JOSE.JWK.to_pem() |> elem(1)]] == ed25519_compact_list
    assert [jwk_ed25519] == JWK.compact_to_list(ed25519_compact_list)

    # Ed25519 with map
    ed25519_compact_with_map = JWK.to_compact(jwk_ed25519, use_map: true)
    assert [kid, alg, key_ed25519 |> JOSE.JWK.to_map() |> elem(1)] == ed25519_compact_with_map
    assert jwk_ed25519 == JWK.from_compact(ed25519_compact_with_map)
    ed25519_compact_list_with_map = JWK.list_to_compact([jwk_ed25519], use_map: true)

    assert [[kid, alg, key_ed25519 |> JOSE.JWK.to_map() |> elem(1)]] ==
             ed25519_compact_list_with_map

    assert [jwk_ed25519] == JWK.compact_to_list(ed25519_compact_list_with_map)
  end

  test "Ed448" do
    alg = "Ed448"
    kid = "Ed448_202009"
    # ref. https://tools.ietf.org/html/rfc8037#appendix-A
    ed448_public_map = %{
      "kty" => "OKP",
      "crv" => "X448",
      "x" => "mwj3zDG34-Z9ItWuoSEHSic70rg94Jxj-qc9LCLF2bvINmRyQdlT1AxbEtqIEg1TF3-A5TLEH6A"
    }

    key_ed448 = JOSE.JWK.from_map(ed448_public_map)
    jwk_ed448 = JWK.new([kid, alg, key_ed448])

    # Ed448 with pem
    ed448_compact = JWK.to_compact(jwk_ed448)
    assert [kid, alg, key_ed448 |> JOSE.JWK.to_pem() |> elem(1)] == ed448_compact
    assert jwk_ed448 == JWK.from_compact(ed448_compact)
    ed448_compact_list = JWK.list_to_compact([jwk_ed448])
    assert [[kid, alg, key_ed448 |> JOSE.JWK.to_pem() |> elem(1)]] == ed448_compact_list
    assert [jwk_ed448] == JWK.compact_to_list(ed448_compact_list)

    # Ed448 with map
    ed448_compact_with_map = JWK.to_compact(jwk_ed448, use_map: true)
    assert [kid, alg, key_ed448 |> JOSE.JWK.to_map() |> elem(1)] == ed448_compact_with_map
    assert jwk_ed448 == JWK.from_compact(ed448_compact_with_map)
    ed448_compact_list_with_map = JWK.list_to_compact([jwk_ed448], use_map: true)
    assert [[kid, alg, key_ed448 |> JOSE.JWK.to_map() |> elem(1)]] == ed448_compact_list_with_map
    assert [jwk_ed448] == JWK.compact_to_list(ed448_compact_list_with_map)
  end

  test "find_key_to_issue" do
    config = [
      kid: "kid20200914",
      keys: [
        [
          "kid20200914",
          "HS256",
          "7KE00igphFhgrU+pgZzZ/7jhNLxmSrba7hGeAFouN+VxYtDiXGYVR0eQ5jQIu6RysP0lsJk9QsUjXQ6F/HeNyivRud+46UOymMBkEo+5yv6mXksvgoZYXcwMckSyW2lz9GHLnnaX+vt78rqSsSSII6IKwvEayJXMCUvhFUO/UTFiY6GIHmJ1zZdOhUQz8OrFaRZos3ip3i4N4WWxm5d4N42KbDQHxb3oDwRDC6mDCu3+7vHBjnNF5dxcfYnUyQAxwDmUFLmnnogJ9rZyLXhbgb+1XtfgWW5CIuPtFXRd+14GRV/U+toUeV6atY3RgrsGCpowKherdr8Xbse6QraOsw"
        ]
      ]
    ]

    key_to_issue = JWK.find_key_to_issue(config)
    assert key_to_issue.kid == config |> Keyword.fetch!(:kid)
    assert [JWK.to_compact(key_to_issue)] == config |> Keyword.fetch!(:keys)

    config = [
      kid: "kid20200914_not_exists",
      keys: [
        [
          "kid20200914",
          "HS256",
          "7KE00igphFhgrU+pgZzZ/7jhNLxmSrba7hGeAFouN+VxYtDiXGYVR0eQ5jQIu6RysP0lsJk9QsUjXQ6F/HeNyivRud+46UOymMBkEo+5yv6mXksvgoZYXcwMckSyW2lz9GHLnnaX+vt78rqSsSSII6IKwvEayJXMCUvhFUO/UTFiY6GIHmJ1zZdOhUQz8OrFaRZos3ip3i4N4WWxm5d4N42KbDQHxb3oDwRDC6mDCu3+7vHBjnNF5dxcfYnUyQAxwDmUFLmnnogJ9rZyLXhbgb+1XtfgWW5CIuPtFXRd+14GRV/U+toUeV6atY3RgrsGCpowKherdr8Xbse6QraOsw"
        ]
      ]
    ]

    refute JWK.find_key_to_issue(config)
  end

  # TODO: test for fetch!()
end
