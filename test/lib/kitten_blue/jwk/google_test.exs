defmodule KittenBlue.JWK.GoogleTest do
  use ExUnit.Case
  doctest KittenBlue.JWK.Google

  import Mock

  @google_jwks_body """
  {
   \"keys\": [
    {
     \"kty\": \"RSA\",
     \"alg\": \"RS256\",
     \"use\": \"sig\",
     \"kid\": \"4ef5118b0800bd60a4194186dcb538fc66e5eb34\",
     \"n\": \"4ZSPB8TO7y3xZF_GxB_JSx_yBEtNs0mDilLvesSLLypYmxt4U7Dxk-vLAf1IVRwaZeeqQRIhrKJjljIqd33tVwfAp5PinjUm7lHi-ufZ_VNQw3uJA5_3tmkMWaLcvdRcILFMlVfBcESp-R5mcF6-bMeYH0n3D5CCJKspIqDERD1gQxfVxWDzafyrqkIROXKEtv3rMe7Z9Yc4mBsL02G6dDKVbjSxvkZ14wMykXEnGkfIiTUSiH8Qm1rdniZigPv2Pa2uSnJ94V-tIDHigjkXR7Cfun4Z38KZdSDRNgJr-m41Pu-plX98j59iGvVyaKP24ZbukGIJRPHYn06xkQeoWw\",
     \"e\": \"AQAB\"
    },
    {
     \"kty\": \"RSA\",
     \"alg\": \"RS256\",
     \"use\": \"sig\",
     \"kid\": \"4129db2ea1860d2e871ee48506287fb05b04ca3f\",
     \"n\": \"sxorUSxfZZjQL1mDr1rtbNGJE9lbVMiBmNZFqLhnQaefTfqMO3YgSlb_cptw5wS2Dn4phGNzjBaO1Hg5572mEqsmPl5z9MmybIOuqWXxYyIiCGWH3hoR2VPJ-1bN-SdszHb4ZWadXCCYqnHS216nrvHZK8vJyQ7XCchw43O00LC5Iwi2eKspQEj8YDQSZFsd7Mp2ULhKXVPyKeLH06aenBZZFwgjw8bow7MXS4uUkg4NOeH2iHNxclOYycg6Z87QrTVzHGBo9r-6s1XRTFh-rqcZC8RnR62wkPqB2AEHctOof_ZtaaDTZ1Xw7db8dRhhCnFkpiK_1d8c9N2Vm7Frxw\",
     \"e\": \"AQAB\"
    }
   ]
  }
  """

  test "fetch!" do
    with_mock HTTPoison,
      get: fn _ ->
        {:ok, %HTTPoison.Response{status_code: 200, body: @google_jwks_body}}
      end do
      assert KittenBlue.JWK.Google.fetch!() ==
               [
                 %KittenBlue.JWK{
                   alg: "RS256",
                   key: %JOSE.JWK{
                     fields: %{
                       "alg" => "RS256",
                       "kid" => "4ef5118b0800bd60a4194186dcb538fc66e5eb34",
                       "use" => "sig"
                     },
                     keys: :undefined,
                     kty:
                       {:jose_jwk_kty_rsa,
                        {:RSAPublicKey,
                         28_476_875_648_721_430_364_188_748_069_991_806_407_446_391_450_373_045_237_923_762_311_151_009_162_921_226_253_790_824_442_505_385_585_760_732_916_607_116_438_838_248_229_723_204_601_135_715_042_657_593_479_636_219_565_745_251_068_995_383_455_309_324_246_029_645_697_720_081_638_829_054_979_172_310_837_551_569_227_970_489_185_383_795_840_331_251_273_817_798_301_830_005_422_761_396_312_919_579_380_879_507_526_326_553_332_110_468_129_972_850_911_213_822_427_291_482_233_788_412_930_127_022_336_316_623_384_602_807_587_333_085_533_862_008_937_303_422_811_962_712_539_911_685_812_228_824_633_770_949_283_643_459_223_554_618_469_656_343_403_152_537_435_626_750_336_345_544_118_558_104_593_194_249_902_094_334_930_123_144_035_611_712_340_631_611_229_262_692_299_252_575_582_560_206_205_278_645_742_069_502_946_607_521_835_099,
                         65537}}
                   },
                   kid: "4ef5118b0800bd60a4194186dcb538fc66e5eb34"
                 },
                 %KittenBlue.JWK{
                   alg: "RS256",
                   key: %JOSE.JWK{
                     fields: %{
                       "alg" => "RS256",
                       "kid" => "4129db2ea1860d2e871ee48506287fb05b04ca3f",
                       "use" => "sig"
                     },
                     keys: :undefined,
                     kty:
                       {:jose_jwk_kty_rsa,
                        {:RSAPublicKey,
                         22_609_561_106_030_035_864_482_994_811_877_141_824_726_126_803_777_462_187_648_248_944_200_098_073_331_236_741_294_232_586_553_300_034_895_012_108_018_434_924_729_133_961_311_183_119_141_914_600_651_954_926_309_301_332_274_897_870_471_122_898_299_742_307_430_511_282_554_878_657_777_308_136_016_225_973_120_369_034_252_221_550_856_774_547_365_225_662_288_681_658_668_758_322_854_479_413_570_330_389_061_522_515_472_701_665_508_175_326_183_008_659_994_223_993_772_082_779_679_322_909_193_619_920_243_402_323_372_013_460_399_491_079_488_825_891_466_897_860_506_499_022_502_474_569_809_346_311_328_649_517_115_778_556_011_555_295_770_068_761_196_334_945_203_754_564_406_086_391_916_223_828_979_710_434_236_708_178_064_890_005_597_548_004_735_093_378_516_718_512_005_576_664_304_324_911_503_655_030_914_082_941_717_001_104_327,
                         65537}}
                   },
                   kid: "4129db2ea1860d2e871ee48506287fb05b04ca3f"
                 }
               ]
    end
  end
end
