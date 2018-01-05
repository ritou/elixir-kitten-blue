defmodule KittenBlue.Mixfile do
  use Mix.Project

  def project do
    [
      app: :kitten_blue,
      version: "0.1.1",
      elixir: "~> 1.4.5",
      start_permanent: Mix.env == :prod,
      description: "KittenBlue is a JOSE wrapper library that makes JWT implementation simpler for Elixir.",
      package: [
        maintainers: ["Ryo Ito"],
        licenses: ["MIT"],
        links: %{"GitHub" => "https://github.com/ritou/elixir-kitten-blue"}
      ],
      deps: deps()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger, :jose, :poison]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      # {:dep_from_hexpm, "~> 0.3.0"},
      # {:dep_from_git, git: "https://github.com/elixir-lang/my_dep.git", tag: "0.1.0"},
      {:jose, "~> 1.8.4"},
      {:poison, "~> 3.1.0"},

      # for docs
      {:ex_doc, "~> 0.16", only: :dev, runtime: false},
    ]
  end
end
