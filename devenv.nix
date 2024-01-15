{ pkgs, ... }:

{
  # https://devenv.sh/basics/
  # env.GREET = "devenv";

  # https://devenv.sh/packages/
  packages = [ pkgs.git pkgs.sing-box];

  # https://devenv.sh/scripts/
  # scripts.hello.exec = "echo hello from $GREET";



  # https://devenv.sh/languages/
  languages.python = {
    enable = true;
    # version = "3.11.3";

    venv.enable = true;
    venv.requirements = ./requirements.txt;
  };

  # https://devenv.sh/pre-commit-hooks/
  # pre-commit.hooks.shellcheck.enable = true;

  # https://devenv.sh/processes/
  # processes.ping.exec = "ping example.com";

  # See full reference at https://devenv.sh/reference/options/
}
