defmodule KittenBlue.JWK.AppleTest do
  use ExUnit.Case

  import Mox
  setup :verify_on_exit!

  @apple_jwks_body """
  {
    "keys": [
      {
        "kty": "RSA",
        "kid": "86D88Kf",
        "use": "sig",
        "alg": "RS256",
        "n": "iGaLqP6y-SJCCBq5Hv6pGDbG_SQ11MNjH7rWHcCFYz4hGwHC4lcSurTlV8u3avoVNM8jXevG1Iu1SY11qInqUvjJur--hghr1b56OPJu6H1iKulSxGjEIyDP6c5BdE1uwprYyr4IO9th8fOwCPygjLFrh44XEGbDIFeImwvBAGOhmMB2AD1n1KviyNsH0bEB7phQtiLk-ILjv1bORSRl8AK677-1T8isGfHKXGZ_ZGtStDe7Lu0Ihp8zoUt59kx2o9uWpROkzF56ypresiIl4WprClRCjz8x6cPZXU2qNWhu71TQvUFwvIvbkE1oYaJMb0jcOTmBRZA2QuYw-zHLwQ",
        "e": "AQAB"
      },
      {
        "kty": "RSA",
        "kid": "eXaunmL",
        "use": "sig",
        "alg": "RS256",
        "n": "4dGQ7bQK8LgILOdLsYzfZjkEAoQeVC_aqyc8GC6RX7dq_KvRAQAWPvkam8VQv4GK5T4ogklEKEvj5ISBamdDNq1n52TpxQwI2EqxSk7I9fKPKhRt4F8-2yETlYvye-2s6NeWJim0KBtOVrk0gWvEDgd6WOqJl_yt5WBISvILNyVg1qAAM8JeX6dRPosahRVDjA52G2X-Tip84wqwyRpUlq2ybzcLh3zyhCitBOebiRWDQfG26EH9lTlJhll-p_Dg8vAXxJLIJ4SNLcqgFeZe4OfHLgdzMvxXZJnPp_VgmkcpUdRotazKZumj6dBPcXI_XID4Z4Z3OM1KrZPJNdUhxw",
        "e": "AQAB"
      }
    ]
  }
  """

  test "fetch!" do
    Mox.stub(KittenBlue.Mox.Http, :get, fn _ ->
      {:ok, %HTTPoison.Response{status_code: 200, body: @apple_jwks_body}}
    end)

    assert KittenBlue.JWK.Apple.fetch!() ==
             [
               %KittenBlue.JWK{
                 alg: "RS256",
                 key: %JOSE.JWK{
                   fields: %{"alg" => "RS256", "kid" => "86D88Kf", "use" => "sig"},
                   keys: :undefined,
                   kty:
                     {:jose_jwk_kty_rsa,
                      {:RSAPublicKey,
                       17_218_976_569_472_171_392_328_766_014_351_377_623_938_190_083_704_822_988_840_858_688_583_589_896_863_690_045_137_023_711_927_931_738_801_630_749_991_914_274_954_014_356_859_870_680_594_196_182_611_436_747_369_851_336_392_150_075_102_120_538_286_646_249_274_018_948_394_939_836_954_815_229_462_134_159_727_313_036_618_616_032_886_754_027_200_534_323_811_097_683_662_906_642_261_006_948_466_488_145_990_076_973_456_988_733_603_209_200_724_856_954_702_255_734_860_429_888_106_995_022_522_513_220_031_897_987_764_861_386_973_776_593_534_699_456_365_388_097_222_751_247_511_386_677_812_517_323_312_227_868_237_294_568_748_794_665_988_814_638_685_917_058_844_978_108_485_387_332_854_052_607_802_543_387_482_783_439_171_585_055_095_101_620_099_686_424_858_380_607_382_460_209_305_193_934_705_911_563_703_225_852_424_512_195_521,
                       65537}}
                 },
                 kid: "86D88Kf"
               },
               %KittenBlue.JWK{
                 alg: "RS256",
                 key: %JOSE.JWK{
                   fields: %{"alg" => "RS256", "kid" => "eXaunmL", "use" => "sig"},
                   keys: :undefined,
                   kty:
                     {:jose_jwk_kty_rsa,
                      {:RSAPublicKey,
                       28_506_959_526_187_058_747_258_525_626_430_938_169_704_725_204_900_526_126_844_083_433_565_751_408_411_494_176_847_637_835_421_193_860_534_595_320_364_447_575_403_468_743_566_499_123_150_300_411_809_834_024_184_195_777_130_663_440_969_659_283_758_913_985_881_923_388_671_973_516_521_122_022_988_964_740_033_971_585_857_996_186_125_352_277_170_962_488_494_163_509_421_647_472_675_123_477_144_074_010_130_241_049_022_712_224_851_924_853_667_700_032_097_975_111_612_938_674_339_911_163_977_966_896_126_177_819_217_844_243_460_102_664_711_470_062_131_611_845_259_215_719_572_214_376_544_337_566_036_425_374_345_989_397_224_110_217_335_993_021_299_491_318_557_930_102_279_952_890_712_915_227_836_029_514_247_217_600_545_540_614_032_933_399_445_683_174_911_113_458_307_244_986_296_233_260_868_205_395_173_861_403_326_852_440_519,
                       65537}}
                 },
                 kid: "eXaunmL"
               }
             ]
  end
end
