{
  description = "Python venv development template";

  inputs = {
    utils.url = "github:numtide/flake-utils";
    flake-parts.url = "github:hercules-ci/flake-parts";
    treefmt-nix = {
      url = "github:numtide/treefmt-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    devshell.url = "github:numtide/devshell";

  };

  outputs =
    inputs@{
      self,
      nixpkgs,
      flake-parts,
      treefmt-nix,
      ...
    }:
    # https://flake.parts/module-arguments.html
    flake-parts.lib.mkFlake { inherit inputs; } (
      top@{
        config,
        withSystem,
        moduleWithSystem,
        ...
      }:
      {
        imports = [
          # Optional: use external flake logic, e.g.
          # inputs.foo.flakeModules.default
          inputs.treefmt-nix.flakeModule
          inputs.devshell.flakeModule
        ];
        flake = {
          # Put your original flake attributes here.
        };
        systems = [
          # systems for which you want to build the `perSystem` attributes
          "x86_64-linux"
          "aarch64-darwin"
          # ...
        ];
        perSystem =
          { config, pkgs, ... }:
          {
            devshells.default =
              let
                pyPkgs =
                  pythonPackages: with pythonPackages; [
                    requests
                    pyyaml
                  ];
              in
              {

                packages = [
                  pkgs.sing-box
                  pkgs.mosdns
                  (pkgs.python3.withPackages pyPkgs)
                ];
              };
            treefmt = {
              # projectRootFile = "LICENSE.md";
              programs.nixfmt.enable = pkgs.lib.meta.availableOn pkgs.stdenv.buildPlatform pkgs.nixfmt-rfc-style.compiler;
              programs.nixfmt.package = pkgs.nixfmt-rfc-style;
              programs.shellcheck.enable = true;
              programs.deno.enable = true;
              programs.ruff.check = true;
              programs.ruff.format = true;
              settings.formatter.shellcheck.options = [
                "-s"
                "bash"
              ];

              settings.formatter.ruff-check.priority = 1;
              settings.formatter.ruff-format.priority = 2;
            };
          };
      }
    );
}
