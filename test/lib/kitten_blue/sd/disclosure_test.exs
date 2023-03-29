defmodule KittenBlue.SD.DisclosureTest do
  use ExUnit.Case

  alias KittenBlue.SD.Disclosure

  describe "new/3" do
    test "raises ArgumentError when claim_name is nil" do
      assert_raise ArgumentError, fn -> Disclosure.new(nil, "value") end
    end

    test "raises ArgumentError when claim_value is nil" do
      assert_raise ArgumentError, fn -> Disclosure.new("name", nil) end
    end

    test "creates a new Disclosure struct with default salt" do
      disclosure = Disclosure.new("name", "value")
      assert disclosure.salt
      assert "name" == disclosure.claim_name
      assert "value" == disclosure.claim_value
    end

    test "creates a new Disclosure struct with custom salt" do
      disclosure = Disclosure.new("name", "value", "custom_salt")
      assert "custom_salt" == disclosure.salt
      assert "name" == disclosure.claim_name
      assert "value" == disclosure.claim_value
    end
  end

  describe "generate_json/1" do
    test "generates JSON from Disclosure struct" do
      disclosure = Disclosure.new("name", "value", "salt")
      expected_json = Jason.encode!(["salt", "name", "value"])
      assert expected_json == disclosure.json
    end
  end

  describe "generate_disclosure/1" do
    test "generates disclosure byte array from JSON" do
      disclosure = Disclosure.new("name", "value", "salt")

      expected_disclosure =
        ["salt", "name", "value"]
        |> Jason.encode!()
        |> String.to_charlist()
        |> :unicode.characters_to_binary()

      assert expected_disclosure == disclosure.disclosure
    end
  end
end
