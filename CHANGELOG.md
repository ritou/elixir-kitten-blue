# Changelog

## 0.9.0

* Add helper module for OAuth DPoP

## 0.8.0

* Suppress warnings on compilation (thanks to k-asm)
* Update CI versions matrix
  * Add Latest OTP Version (thanks to k-asm)
  * Remove Old Elixir Version

## 0.7.0

* Add an optional filed to JWK to handle X.509 parameters (thanks to k-asm)

## 0.6.0

* Add function to verify JWS token with x5c header using JWK object (thanks to k-asm)

## 0.5.0

* Make the configuration for KittenBlue.JWK optional.

## 0.4.0

* Good bye travis, and hello actions

## 0.3.0

* Use Scratcher to remove dependency on HTTPoison

## 0.2.1

* Add JWK.find_key_to_issue

## 0.2.0

* Update jose version and support other algs at jwk

## 0.1.8

* Use Jason as JSON module and relax some deps (thanks to enerick)

## 0.1.7

* Support Apple's JWKs

## 0.1.6

* Add function for varidation standard claims

## 0.1.5

* Add header parameter for optional param when generation/verification JWS

## 0.1.4 

* Relax a dependency requirement of :httpoison (thanks to enerick)
* remove doctest from JWK.GoogleTest (thanks to enerick)

## 0.1.3

* update deps
* support google jwks handling module

## 0.1.2 (2018-04-09)

* Add functions for converting to compact storable format.

## 0.1.1 (2018-01-05)

* Delete initial module by `mix new` command

## 0.1.0 (2018-01-05)

* Initial Release
