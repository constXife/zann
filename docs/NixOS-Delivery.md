---
title: NixOS Secret Delivery
description: Deliver Zann machine secrets to systemd services as generation-consistent credentials.
---

# NixOS secret delivery

The flake exports `nixosModules.zann-delivery`. The module keeps secret values
out of Nix evaluation, the Nix store, unit arguments and environment variables.
It resolves a value-free profile at runtime and passes one immutable generation
to the target through systemd credentials.

## Configuration

Import the module from your flake and declare exact references:

```nix
{
  inputs.zann.url = "github:constXife/zann";

  outputs = { self, nixpkgs, zann, ... }: {
    nixosConfigurations.host = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        zann.nixosModules.zann-delivery
        ({ pkgs, ... }: {
          services.zann.delivery = {
            enable = true;
            profiles.web = {
              vault = "infra";
              serverUrl = "https://zann.example.com";
              serverFingerprint = "sha256:REPLACE_WITH_PINNED_FINGERPRINT";

              # A runtime string, deliberately not a Nix path.
              tokenFile = "/run/keys/zann-web-service-account";
              targetUnit = "web.service";

              secrets = {
                database-password = "services/web/database";
                session-key = "services/web/session-key";
              };
            };
          };

          systemd.services.web = {
            wantedBy = [ "multi-user.target" ];
            environment = {
              DATABASE_PASSWORD_FILE = "%d/zann-web_database-password";
              SESSION_KEY_FILE = "%d/zann-web_session-key";
            };
            serviceConfig.ExecStart = "${pkgs.example}/bin/example";
          };
        })
      ];
    };
  };
}
```

Replace `pkgs.example` with the actual service package. The process receives
only credential file paths. It reads the values from `$CREDENTIALS_DIRECTORY`
or the equivalent `%d/...` paths; do not copy them into environment variables.

The service-account scope must grant `read` for every referenced path. The
token file must already exist below `/run/` when the target starts and be
readable by the system service manager. Use a runtime secret provisioner such
as your existing host bootstrap, not `pkgs.writeText`.

## Publication and activation

For profile `web`, the module creates:

- `zann-delivery-web-bootstrap.service`, required before `web.service` and
  retained as an active oneshot after successful online publication;
- `zann-delivery-web-refresh.service`, the explicit manual refresh entry point;
- `zann-delivery-web-refresh.timer`, every 15 minutes by default.

The runtime sequence is fail-closed:

1. systemd supplies the service-account token to the delivery unit through its
   own `LoadCredential=` directory;
2. the CLI pins `serverFingerprint`, performs one bounded `batch/get`, and
   publishes a complete private generation below `/run/zann-delivery/web/`;
3. the module atomically installs a runtime drop-in whose directory-form
   `LoadCredential=` references that exact immutable generation UUID;
4. `systemctl daemon-reload` succeeds;
5. an already running target is explicitly restarted so systemd creates a new
   credential directory from the new generation.

At boot, failure before step 4 prevents the target from starting. A periodic
failure leaves the running target and its previous systemd credential copies
untouched. There is no stale offline fallback.

Unchanged complete generations are reused, so the timer does not restart the
target when the values and target set are identical. Concurrent
bootstrap/manual/timer publications are serialized with a private runtime
lock. A private activation marker is advanced only after `daemon-reload` and
the configured target action succeed, so a retry completes a partially failed
activation instead of silently accepting it.

Run a manual refresh with:

```bash
systemctl start zann-delivery-web-refresh.service
```

Set `refreshInterval = null` to disable only the timer; manual refresh remains
available. Restart is mandatory: a systemd reload does not recreate
`$CREDENTIALS_DIRECTORY` and therefore cannot activate a new credential
generation safely.

## Limits and security properties

- One profile references 1–64 flat credential names from one vault.
- systemd delivery caps aggregate value bytes at 1 MiB before publication.
- Profile documents stored by Nix contain references only.
- Secret values never enter the Nix store, runtime drop-in, argv, environment,
  stdout or journal.
- Delivery units run as root only because they install a runtime systemd
  drop-in; capabilities are removed and filesystem writes are limited to the
  private runtime root and the exact target unit's runtime drop-in directory.
- Runtime drop-ins for removed or disabled profiles are deleted during NixOS
  activation.
- Values remain plaintext in the retained private `/run` generations and in
  systemd's protected credential copies. Set `retainGenerations = 1` if local
  rollback is unnecessary.
- Revocation cannot remove values already held by a running process.

`allowInsecure = true` is required for HTTP or invalid TLS and should only be
used for isolated development systems.

## Repository smoke test

The flake includes two QEMU NixOS checks. The fast module smoke test uses a
deterministic protocol fixture and covers boot gating, unchanged refreshes,
credential replacement through restart, backend failure and retry, and managed
drop-in cleanup after disabling delivery:

```bash
nix build .#checks.x86_64-linux.zann-delivery-vm --no-link --print-build-logs
```

The real-server integration check boots PostgreSQL, runs the actual migrations
and privileged provisioning commands, exchanges a real scoped service-account
token with `zann-server`, resolves the profile through the production secrets
API and passes the result through systemd credentials. It also exercises an
out-of-scope denial, database-backed secret update, server outage and recovery:

```bash
nix build .#checks.x86_64-linux.zann-delivery-real-server-vm --no-link --print-build-logs
```
