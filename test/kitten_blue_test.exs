defmodule KittenBlueTest do
  use ExUnit.Case
  doctest KittenBlue

  test "greets the world" do
    assert KittenBlue.hello() == :world
  end
end
