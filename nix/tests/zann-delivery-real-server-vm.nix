{
  module,
  pkgs,
  zannCli,
  zannServer,
}:

let
  fingerprint = "sha256:zann-delivery-real-server-test";
  serverAddress = "http://127.0.0.1:18080";
  databaseUrl = "postgresql:///zann?host=/run/postgresql";

  serverConfig = pkgs.writeText "zann-delivery-real-server.yaml" (
    builtins.toJSON {
      auth = {
        mode = "internal";
        internal = {
          enabled = true;
          registration = "disabled";
        };
      };
      policy.file = "${../../config/policies.default.yaml}";
      server = {
        inherit fingerprint;
        master_key_mode = "external";
        personal_vaults_enabled = false;
      };
    }
  );

  commonEnvironment = {
    ZANN_ADDR = "127.0.0.1:18080";
    ZANN_CONFIG_PATH = serverConfig;
    ZANN_DB_URL = databaseUrl;
    RUST_LOG = "zann_server=info,sqlx=warn";
  };

  serverWrapper = pkgs.writeShellApplication {
    name = "zann-delivery-test-server";
    runtimeInputs = [ zannServer ];
    text = ''
      export ZANN_PASSWORD_PEPPER_FILE="$CREDENTIALS_DIRECTORY/password-pepper"
      export ZANN_TOKEN_PEPPER_FILE="$CREDENTIALS_DIRECTORY/token-pepper"
      export ZANN_SMK_FILE="$CREDENTIALS_DIRECTORY/server-master-key"
      export ZANN_IDENTITY_KEY_FILE="$CREDENTIALS_DIRECTORY/identity-key"
      exec zann-server
    '';
  };

  migrate = pkgs.writeShellApplication {
    name = "zann-delivery-test-migrate";
    runtimeInputs = [ zannServer ];
    text = ''
      exec zann-server migrate
    '';
  };

  provision = pkgs.writeShellApplication {
    name = "zann-delivery-test-provision";
    runtimeInputs = [ zannServer ];
    text = ''
      export ZANN_PASSWORD_PEPPER_FILE="$CREDENTIALS_DIRECTORY/password-pepper"
      export ZANN_TOKEN_PEPPER_FILE="$CREDENTIALS_DIRECTORY/token-pepper"
      export ZANN_SMK_FILE="$CREDENTIALS_DIRECTORY/server-master-key"
      export ZANN_IDENTITY_KEY_FILE="$CREDENTIALS_DIRECTORY/identity-key"

      zann-server provision ensure-vault --name Infrastructure --slug infra
      zann-server provision set-field \
        --vault infra \
        --path services/web/database \
        --key value \
        --kind password \
        --value-file "$CREDENTIALS_DIRECTORY/database-password"
      zann-server provision set-field \
        --vault infra \
        --path services/admin/control-key \
        --key value \
        --kind password \
        --value-file "$CREDENTIALS_DIRECTORY/control-key"
      zann-server provision ensure-token \
        web-delivery \
        infra:services/web/database \
        read \
        --write-token-file /run/zann-real-test/zann-web
    '';
  };

  waitForServer = pkgs.writeShellApplication {
    name = "zann-delivery-test-wait-for-server";
    runtimeInputs = [ pkgs.curl ];
    text = ''
      for _ in $(seq 1 60); do
        if curl --fail --silent --show-error ${serverAddress}/health >/dev/null; then
          exit 0
        fi
        sleep 1
      done
      echo "zann-server did not become ready" >&2
      exit 1
    '';
  };

  consumer = pkgs.writeShellApplication {
    name = "zann-delivery-real-test-consumer";
    runtimeInputs = [ pkgs.coreutils ];
    text = ''
      install -d -m 0700 /run/zann-delivery-real-test-consumer
      value="$(<"$CREDENTIALS_DIRECTORY/zann-web_database-password")"
      printf '%s\n' "$value" >> /run/zann-delivery-real-test-consumer/starts
      printf '%s\n' "$value" > /run/zann-delivery-real-test-consumer/current
      exec sleep infinity
    '';
  };

  serverCredentials = [
    "password-pepper:/run/zann-real-test/password-pepper"
    "token-pepper:/run/zann-real-test/token-pepper"
    "server-master-key:/run/zann-real-test/server-master-key"
    "identity-key:/run/zann-real-test/identity-key"
  ];
in
pkgs.testers.runNixOSTest {
  name = "zann-delivery-real-server-vm";

  nodes.machine =
    { lib, ... }:
    {
      imports = [ module ];

      users.groups.zann = { };
      users.users.zann = {
        isSystemUser = true;
        group = "zann";
      };

      services.postgresql = {
        enable = true;
        package = pkgs.postgresql_16;
        ensureDatabases = [ "zann" ];
        ensureUsers = [
          {
            name = "zann";
            ensureDBOwnership = true;
          }
        ];
      };

      systemd.tmpfiles.rules = [
        "d /run/zann-real-test 0700 zann zann -"
        "f+ /run/zann-real-test/password-pepper 0400 zann zann - test-password-pepper"
        "f+ /run/zann-real-test/token-pepper 0400 zann zann - test-token-pepper"
        "f+ /run/zann-real-test/server-master-key 0400 zann zann - AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        "f+ /run/zann-real-test/identity-key 0400 zann zann - AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
        "f+ /run/zann-real-test/database-password 0400 zann zann - real-one-secret"
        "f+ /run/zann-real-test/control-key 0400 zann zann - admin-control-secret"
      ];

      systemd.services.zann-test-migrate = {
        description = "Migrate the real Zann delivery test database";
        requires = [ "postgresql-setup.service" ];
        after = [ "postgresql-setup.service" ];
        environment = commonEnvironment;
        serviceConfig = {
          Type = "oneshot";
          User = "zann";
          Group = "zann";
          ExecStart = lib.getExe migrate;
        };
      };

      systemd.services.zann-test-provision = {
        description = "Provision the real Zann delivery test fixtures";
        requires = [ "zann-test-migrate.service" ];
        after = [
          "zann-test-migrate.service"
          "systemd-tmpfiles-setup.service"
        ];
        environment = commonEnvironment;
        serviceConfig = {
          Type = "oneshot";
          User = "zann";
          Group = "zann";
          ExecStart = lib.getExe provision;
          LoadCredential = serverCredentials ++ [
            "database-password:/run/zann-real-test/database-password"
            "control-key:/run/zann-real-test/control-key"
          ];
          UMask = "0077";
        };
      };

      systemd.services.zann-test-server = {
        description = "Real Zann server for delivery integration testing";
        wantedBy = [ "multi-user.target" ];
        requires = [ "zann-test-provision.service" ];
        after = [ "zann-test-provision.service" ];
        environment = commonEnvironment;
        serviceConfig = {
          Type = "simple";
          User = "zann";
          Group = "zann";
          ExecStart = lib.getExe serverWrapper;
          LoadCredential = serverCredentials;
          Restart = "on-failure";
          RestartSec = "1s";
          UMask = "0077";
        };
      };

      systemd.services.zann-test-ready = {
        description = "Wait for the real Zann delivery test server";
        wants = [ "zann-test-server.service" ];
        after = [ "zann-test-server.service" ];
        serviceConfig = {
          Type = "oneshot";
          ExecStart = lib.getExe waitForServer;
          RemainAfterExit = true;
        };
      };

      services.zann.delivery = {
        enable = true;
        package = zannCli;
        profiles.web = {
          vault = "infra";
          secrets.database-password = "services/web/database";
          serverUrl = serverAddress;
          serverFingerprint = fingerprint;
          tokenFile = "/run/zann-real-test/zann-web";
          targetUnit = "web.service";
          refreshInterval = null;
          allowInsecure = true;
          retainGenerations = 2;
        };
      };

      systemd.services.zann-delivery-web-bootstrap = {
        requires = [ "zann-test-ready.service" ];
        after = [ "zann-test-ready.service" ];
      };

      systemd.services.web = {
        description = "Real Zann delivery test consumer";
        wantedBy = [ "multi-user.target" ];
        serviceConfig = {
          Type = "simple";
          ExecStart = lib.getExe consumer;
        };
      };

      virtualisation = {
        memorySize = 1536;
        diskSize = 4096;
      };
    };

  testScript = ''
    start_all()

    with subtest("real server bootstraps PostgreSQL, service account auth, and delivery"):
        machine.wait_for_unit("web.service")
        machine.succeed("curl --fail --silent http://127.0.0.1:18080/health")
        machine.succeed("grep -Fqx real-one-secret /run/zann-delivery-real-test-consumer/current")
        machine.succeed("grep -Fqx real-one-secret /run/credentials/web.service/zann-web_database-password")
        machine.succeed("test \"$(wc -l < /run/zann-delivery-real-test-consumer/starts)\" -eq 1")
        machine.succeed("test \"$(stat -c %a /run/zann-real-test/zann-web)\" = 600")
        machine.succeed("grep -Fq zann_sa_ /run/zann-real-test/zann-web")

    with subtest("plaintext inputs are file-backed and absent from unit command lines"):
        machine.fail("systemctl cat zann-test-provision.service | grep -F real-one-secret")
        machine.fail("systemctl cat zann-delivery-web-bootstrap.service | grep -F zann_sa_")
        machine.fail("systemctl show -p ExecStart zann-test-provision.service | grep -F admin-control-secret")

    with subtest("the exact service-account scope denies another subtree"):
        machine.fail("ZANN_SERVER_FINGERPRINT='${fingerprint}' ${pkgs.lib.getExe zannCli} --insecure --addr '${serverAddress}' --token-file /run/zann-real-test/zann-web secret get services/admin/control-key --vault infra")

    with subtest("real database update publishes a new credential generation"):
        machine.succeed("printf %s real-two-secret > /run/zann-real-test/database-password")
        machine.succeed("systemctl start zann-test-provision.service")
        machine.succeed("systemctl start zann-delivery-web-refresh.service")
        machine.succeed("test \"$(wc -l < /run/zann-delivery-real-test-consumer/starts)\" -eq 2")
        machine.succeed("grep -Fqx real-two-secret /run/zann-delivery-real-test-consumer/current")
        machine.succeed("grep -Fqx real-two-secret /run/credentials/web.service/zann-web_database-password")

    with subtest("server outage preserves the active generation and consumer"):
        machine.succeed("systemctl stop zann-test-server.service")
        machine.fail("systemctl start zann-delivery-web-refresh.service")
        machine.succeed("systemctl is-active --quiet web.service")
        machine.succeed("test \"$(wc -l < /run/zann-delivery-real-test-consumer/starts)\" -eq 2")
        machine.succeed("grep -Fqx real-two-secret /run/zann-delivery-real-test-consumer/current")

    with subtest("delivery recovers after the real server returns"):
        machine.succeed("systemctl start zann-test-server.service")
        machine.succeed("systemctl reset-failed zann-delivery-web-refresh.service")
        machine.succeed("systemctl start zann-delivery-web-refresh.service")
        machine.succeed("test \"$(wc -l < /run/zann-delivery-real-test-consumer/starts)\" -eq 2")
        machine.succeed("grep -Fqx real-two-secret /run/zann-delivery-real-test-consumer/current")
  '';
}
