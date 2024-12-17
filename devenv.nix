{pkgs, ...}: {
  # https://devenv.sh/basics/
  # env.GREET = "devenv";

  # https://devenv.sh/packages/
  packages = with pkgs; [git sing-box];

  # https://devenv.sh/scripts/
  # scripts.hello.exec = "echo hello from $GREET";

  # https://devenv.sh/languages/
  languages.python = {
    enable = true;
    # version = "3.11.3";

    uv = {
      enable = true;
      # sync.enable = true;
    };
  };

  # https://devenv.sh/pre-commit-hooks/
  pre-commit.hooks = {
    # remove un unsed imports
    shellcheck.enable = true;
    # format Python code
    ruff.enable = true;
    ruff-format.enable = true;
  };
  # https://devenv.sh/processes/
  # processes.ping.exec = "ping example.com";

  # See full reference at https://devenv.sh/reference/options/
}
