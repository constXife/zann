{
  module,
  pkgs,
}:

let
  generationOne = "01890f3e-7b6c-7a11-8000-000000000001";
  generationTwo = "01890f3e-7b6c-7a11-8000-000000000002";
  generationThree = "01890f3e-7b6c-7a11-8000-000000000003";

  fakeZann = pkgs.writeShellApplication {
    name = "zann";
    runtimeInputs = [ pkgs.coreutils ];
    text = ''
      for argument in "$@"; do
        if [[ "$argument" == "test-service-token" ]]; then
          echo "service token leaked into argv" >&2
          exit 6
        fi
      done

      output=""
      token_file=""
      while (( $# > 0 )); do
        case "$1" in
          --out)
            output="$2"
            shift 2
            ;;
          --token-file)
            token_file="$2"
            shift 2
            ;;
          --addr|--profile|--retain-generations|--max-total-bytes)
            shift 2
            ;;
          --insecure|--skip-unchanged|delivery|apply)
            shift
            ;;
          *)
            echo "unexpected fake zann argument" >&2
            exit 2
            ;;
        esac
      done

      if [[ -z "$output" || -z "$token_file" ]]; then
        echo "missing delivery arguments" >&2
        exit 2
      fi
      if [[ "$(<"$token_file")" != "test-service-token" ]]; then
        echo "service token credential was not delivered" >&2
        exit 3
      fi
      if [[ ! -e /run/fake-zann/available ]]; then
        echo "fake backend unavailable" >&2
        exit 4
      fi

      value="$(</run/fake-zann/value)"
      case "$value" in
        one-secret) generation=${generationOne} ;;
        two-secret) generation=${generationTwo} ;;
        three-secret) generation=${generationThree} ;;
        *)
          echo "unknown fake secret version" >&2
          exit 5
          ;;
      esac

      if [[ -f "$output/current" ]] && grep -Fqx -- "$generation" "$output/current"; then
        printf '%s\n' "$generation"
        exit 0
      fi

      install -d -m 0700 "$output" "$output/generations"
      temporary="$output/generations/.$generation.tmp"
      install -d -m 0700 "$temporary"
      printf '%s' "$value" > "$temporary/database-password"
      chmod 0600 "$temporary/database-password"
      mv "$temporary" "$output/generations/$generation"

      current_temporary="$output/.current.$generation"
      printf '%s\n' "$generation" > "$current_temporary"
      chmod 0600 "$current_temporary"
      mv -f "$current_temporary" "$output/current"
      printf '%s\n' "$generation"
    '';
  };

  consumer = pkgs.writeShellApplication {
    name = "zann-delivery-test-consumer";
    runtimeInputs = [ pkgs.coreutils ];
    text = ''
      install -d -m 0700 /run/zann-delivery-test-consumer
      value="$(<"$CREDENTIALS_DIRECTORY/zann-web_database-password")"
      printf '%s\n' "$value" >> /run/zann-delivery-test-consumer/starts
      printf '%s\n' "$value" > /run/zann-delivery-test-consumer/current
      exec sleep infinity
    '';
  };
in
pkgs.testers.runNixOSTest {
  name = "zann-delivery-vm";

  nodes.machine =
    { lib, pkgs, ... }:
    {
      imports = [ module ];

      services.zann.delivery = {
        enable = true;
        package = fakeZann;
        profiles.web = {
          vault = "infra";
          secrets.database-password = "services/web/database";
          serverUrl = "https://zann.invalid";
          serverFingerprint = "sha256:test";
          tokenFile = "/run/keys/zann-web";
          targetUnit = "web.service";
          refreshInterval = null;
          retainGenerations = 3;
        };
      };

      systemd.tmpfiles.rules = [
        "f+ /run/keys/zann-web 0600 root root - test-service-token"
        "d /run/fake-zann 0700 root root -"
      ];

      systemd.services.web = {
        description = "Zann delivery VM test consumer";
        wantedBy = [ "multi-user.target" ];
        serviceConfig = {
          Type = "simple";
          ExecStart = lib.getExe consumer;
        };
      };

      specialisation.no-delivery.configuration = {
        services.zann.delivery.enable = lib.mkForce false;
        systemd.services.web = {
          wantedBy = lib.mkForce [ ];
          serviceConfig.ExecStart = lib.mkForce "${pkgs.coreutils}/bin/sleep infinity";
        };
      };
      virtualisation.memorySize = 768;
    };

  testScript = ''
    start_all()
    machine.wait_for_unit("multi-user.target")

    with subtest("initial backend failure gates the target"):
        machine.fail("systemctl is-active --quiet web.service")
        machine.fail("test -e /run/zann-delivery-test-consumer/starts")
        machine.fail("test -e /run/systemd/system/web.service.d/50-zann-delivery-web.conf")

    with subtest("recovery publishes generation one and starts the target"):
        machine.succeed("printf %s one-secret > /run/fake-zann/value")
        machine.succeed("touch /run/fake-zann/available")
        machine.succeed("systemctl reset-failed zann-delivery-web-bootstrap.service web.service")
        machine.succeed("systemctl start web.service")
        machine.wait_for_unit("web.service")
        machine.succeed("grep -Fqx one-secret /run/zann-delivery-test-consumer/current")
        machine.succeed("grep -Fqx one-secret /run/credentials/web.service/zann-web_database-password")
        machine.succeed("grep -Fqx '${generationOne}' /run/zann-delivery/web/activated-generation")

    with subtest("an unchanged refresh does not restart the target"):
        machine.succeed("systemctl start zann-delivery-web-refresh.service")
        machine.succeed("test \"$(wc -l < /run/zann-delivery-test-consumer/starts)\" -eq 1")

    with subtest("a changed generation restarts with new credentials"):
        machine.succeed("printf %s two-secret > /run/fake-zann/value")
        machine.succeed("systemctl start zann-delivery-web-refresh.service")
        machine.succeed("test \"$(wc -l < /run/zann-delivery-test-consumer/starts)\" -eq 2")
        machine.succeed("grep -Fqx two-secret /run/zann-delivery-test-consumer/current")
        machine.succeed("grep -Fqx two-secret /run/credentials/web.service/zann-web_database-password")
        machine.succeed("grep -Fqx '${generationTwo}' /run/zann-delivery/web/activated-generation")

    with subtest("a refresh failure preserves the running generation"):
        machine.succeed("rm /run/fake-zann/available")
        machine.succeed("printf %s three-secret > /run/fake-zann/value")
        machine.fail("systemctl start zann-delivery-web-refresh.service")
        machine.succeed("systemctl is-active --quiet web.service")
        machine.succeed("test \"$(wc -l < /run/zann-delivery-test-consumer/starts)\" -eq 2")
        machine.succeed("grep -Fqx two-secret /run/zann-delivery-test-consumer/current")
        machine.succeed("grep -Fqx '${generationTwo}' /run/zann-delivery/web/activated-generation")

    with subtest("the failed refresh retries and activates generation three"):
        machine.succeed("touch /run/fake-zann/available")
        machine.succeed("systemctl reset-failed zann-delivery-web-refresh.service")
        machine.succeed("systemctl start zann-delivery-web-refresh.service")
        machine.succeed("test \"$(wc -l < /run/zann-delivery-test-consumer/starts)\" -eq 3")
        machine.succeed("grep -Fqx three-secret /run/zann-delivery-test-consumer/current")
        machine.succeed("grep -Fqx three-secret /run/credentials/web.service/zann-web_database-password")
        machine.succeed("grep -Fqx '${generationThree}' /run/zann-delivery/web/activated-generation")

    with subtest("disabling delivery removes the managed runtime drop-in"):
        machine.succeed("test -e /run/systemd/system/web.service.d/50-zann-delivery-web.conf")
        machine.succeed("/run/current-system/specialisation/no-delivery/bin/switch-to-configuration test")
        machine.fail("test -e /run/systemd/system/web.service.d/50-zann-delivery-web.conf")
  '';
}
