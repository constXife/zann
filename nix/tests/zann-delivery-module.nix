{
  module,
  nixpkgs,
  system,
}:

let
  evaluate =
    enable:
    nixpkgs.lib.nixosSystem {
      inherit system;
      modules = [
        module
        (
          { pkgs, ... }:
          {
            boot.isContainer = true;
            system.stateVersion = "26.05";

            services.zann.delivery = {
              inherit enable;
              package = pkgs.writeShellScriptBin "zann" "exit 0";
              profiles.web = {
                vault = "infra";
                secrets.database-password = "services/web/database";
                serverUrl = "https://zann.example.com";
                serverFingerprint = "sha256:test";
                tokenFile = "/run/keys/zann-web";
                targetUnit = "web.service";
              };
            };

            systemd.services.web.serviceConfig.ExecStart = "/bin/true";
          }
        )
      ];
    };

  evaluated = evaluate true;
  disabled = evaluate false;
  cfg = evaluated.config;
  bootstrap = cfg.systemd.services.zann-delivery-web-bootstrap;
  refresh = cfg.systemd.services.zann-delivery-web-refresh;
in
assert bootstrap.serviceConfig.Type == "oneshot";
assert builtins.all (entry: entry.assertion) cfg.assertions;
assert bootstrap.serviceConfig.RemainAfterExit;
assert bootstrap.serviceConfig.LoadCredential == [ "zann-service-token:/run/keys/zann-web" ];
assert builtins.elem "zann-delivery-web-bootstrap.service" cfg.systemd.services.web.requires;
assert
  cfg.systemd.timers.zann-delivery-web-refresh.timerConfig.Unit
  == "zann-delivery-web-refresh.service";
assert builtins.elem "/run/systemd/system/web.service.d" refresh.serviceConfig.ReadWritePaths;
assert builtins.elem "d /run/systemd/system/web.service.d 0755 root root -"
  cfg.systemd.tmpfiles.rules;
assert
  !(nixpkgs.lib.hasInfix "/run/systemd/system/web.service.d/50-zann-delivery-web.conf" disabled.config.system.activationScripts.zannDeliveryDropinsCleanup.text);
evaluated.pkgs.runCommand "zann-delivery-module-eval" { } ''
  touch "$out"
''
