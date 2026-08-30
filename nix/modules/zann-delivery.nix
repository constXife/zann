{
  config,
  lib,
  pkgs,
  ...
}:

let
  inherit (lib)
    mkEnableOption
    mkIf
    mkMerge
    mkOption
    types
    ;
  cfg = config.services.zann.delivery;

  safeProfileName = value: builtins.match "[A-Za-z0-9][A-Za-z0-9_-]*" value != null;
  safeCredentialName = value: builtins.match "[A-Za-z0-9][A-Za-z0-9_.-]*" value != null;
  safeUnitName = value: builtins.match "[A-Za-z0-9][A-Za-z0-9:_.@-]*[.]service" value != null;

  profileType = types.submodule (
    { name, ... }: {
      options = {
        vault = mkOption {
          type = types.nonEmptyStr;
          description = "Exact shared vault name or ID referenced by this profile.";
        };

        secrets = mkOption {
          type = types.attrsOf types.nonEmptyStr;
          description = ''
            Credential filename to exact machine-secret path mapping. Attribute
            names become flat systemd credential suffixes; values are references,
            never secret values.
          '';
          example = {
            database-password = "services/web/database";
            session-key = "services/web/session-key";
          };
        };

        serverUrl = mkOption {
          type = types.nonEmptyStr;
          description = "Pinned Zann server URL.";
        };

        serverFingerprint = mkOption {
          type = types.nonEmptyStr;
          description = "Expected Zann server fingerprint; unattended TOFU is forbidden.";
        };

        tokenFile = mkOption {
          type = types.nonEmptyStr;
          description = ''
            Absolute runtime path to the service-account token. This is a string,
            not a Nix path, so its contents are never copied into the Nix store.
          '';
        };

        targetUnit = mkOption {
          type = types.nonEmptyStr;
          description = "Service unit that consumes the published credentials.";
          example = "web.service";
        };

        credentialPrefix = mkOption {
          type = types.nonEmptyStr;
          default = "zann-${name}";
          description = ''
            Prefix used by systemd's directory-form LoadCredential. A target named
            `database-password` is exposed as `<prefix>_database-password`.
          '';
        };

        retainGenerations = mkOption {
          type = types.ints.between 1 10;
          default = 2;
          description = "Number of complete plaintext generations retained in /run.";
        };

        refreshInterval = mkOption {
          type = types.nullOr types.nonEmptyStr;
          default = "15m";
          description = "systemd OnUnitActiveSec value, or null to disable periodic refresh.";
        };

        randomizedDelaySec = mkOption {
          type = types.nonEmptyStr;
          default = "30s";
          description = "Timer jitter applied to periodic refresh.";
        };

        allowInsecure = mkOption {
          type = types.bool;
          default = false;
          description = "Explicitly allow HTTP or invalid TLS certificates.";
        };
      };
    }
  );

  profileDocument =
    name: profile:
    pkgs.writeText "zann-delivery-${name}.yaml" (
      builtins.toJSON {
        version = 1;
        vault = profile.vault;
        files = lib.mapAttrsToList (target: secret: { inherit secret target; }) profile.secrets;
      }
    );

  runtimeRoot = name: "/run/zann-delivery/${name}";

  deliveryScript =
    name: profile: activateTarget:
    let
      root = runtimeRoot name;
      document = profileDocument name profile;
      insecureFlag = lib.optionalString profile.allowInsecure " --insecure";
    in
    pkgs.writeShellApplication {
      name = "zann-delivery-${name}";
      runtimeInputs = [
        cfg.package
        pkgs.coreutils
        pkgs.gnugrep
        pkgs.systemd
        pkgs.util-linux
      ];
      text = ''
        exec 9>"${root}/publication.lock"
        flock -x 9

        generation="$(${lib.getExe cfg.package}${insecureFlag} \
          --addr ${lib.escapeShellArg profile.serverUrl} \
          --token-file "$CREDENTIALS_DIRECTORY/zann-service-token" \
          delivery apply \
          --profile ${document} \
          --out "${root}/store" \
          --retain-generations ${toString profile.retainGenerations} \
          --skip-unchanged \
          --max-total-bytes 1048576)"

        if [[ ! "$generation" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$ ]]; then
          echo "zann delivery returned an invalid generation identifier" >&2
          exit 1
        fi

        dropin_dir=${lib.escapeShellArg "/run/systemd/system/${profile.targetUnit}.d"}
        dropin="$dropin_dir/50-zann-delivery-${name}.conf"
        activated_marker="${root}/activated-generation"
        credential_line="LoadCredential=${profile.credentialPrefix}:${root}/store/generations/$generation"

        dropin_current=false
        if [[ -f "$dropin" ]] && grep -Fqx -- "$credential_line" "$dropin"; then
          dropin_current=true
        fi
        if "$dropin_current" && [[ -f "$activated_marker" ]] && grep -Fqx -- "$generation" "$activated_marker"; then
          exit 0
        fi

        if ! "$dropin_current"; then
          install -d -m 0755 "$dropin_dir"
          temporary="$(mktemp "$dropin_dir/.50-zann-delivery-${name}.XXXXXX")"
          trap 'rm -f "$temporary"' EXIT
          printf '[Service]\n%s\n' "$credential_line" > "$temporary"
          chmod 0644 "$temporary"
          mv -f "$temporary" "$dropin"
          trap - EXIT
        fi

        systemctl daemon-reload
        activation_complete=false
        ${lib.optionalString activateTarget ''
          if systemctl is-active --quiet ${lib.escapeShellArg profile.targetUnit}; then
            systemctl restart ${lib.escapeShellArg profile.targetUnit}
            activation_complete=true
          fi
        ''}
        if ! systemctl is-active --quiet ${lib.escapeShellArg profile.targetUnit}; then
          activation_complete=true
        fi

        if "$activation_complete"; then
          temporary="$(mktemp "${root}/.activated-generation.XXXXXX")"
          trap 'rm -f "$temporary"' EXIT
          printf '%s\n' "$generation" > "$temporary"
          chmod 0600 "$temporary"
          mv -f "$temporary" "$activated_marker"
          trap - EXIT
        fi
      '';
    };

  hardenedService = name: profile: script: {
    description = "Publish Zann delivery profile ${name}";
    wants = [ "network-online.target" ];
    after = [
      "network-online.target"
      "systemd-tmpfiles-setup.service"
    ];
    environment = {
      HOME = "${runtimeRoot name}/home";
      ZANN_SERVER_FINGERPRINT = profile.serverFingerprint;
    };
    serviceConfig = {
      Type = "oneshot";
      ExecStart = lib.getExe script;
      LoadCredential = [ "zann-service-token:${profile.tokenFile}" ];
      RuntimeDirectory = "zann-delivery/${name}";
      RuntimeDirectoryMode = "0700";
      RuntimeDirectoryPreserve = "yes";
      UMask = "0077";
      TimeoutStartSec = "2min";

      CapabilityBoundingSet = "";
      LockPersonality = true;
      MemoryDenyWriteExecute = true;
      NoNewPrivileges = true;
      PrivateDevices = true;
      PrivateMounts = true;
      PrivateTmp = true;
      ProcSubset = "pid";
      ProtectClock = true;
      ProtectControlGroups = true;
      ProtectHome = true;
      ProtectHostname = true;
      ProtectKernelLogs = true;
      ProtectKernelModules = true;
      ProtectKernelTunables = true;
      ProtectProc = "invisible";
      ProtectSystem = "strict";
      ReadWritePaths = [
        (runtimeRoot name)
        "/run/systemd/system/${profile.targetUnit}.d"
      ];
      RestrictAddressFamilies = [
        "AF_UNIX"
        "AF_INET"
        "AF_INET6"
      ];
      RestrictRealtime = true;
      RestrictNamespaces = true;
      RestrictSUIDSGID = true;
      SystemCallArchitectures = "native";
    };
  };

  profileConfig =
    name: profile:
    let
      bootstrapName = "zann-delivery-${name}-bootstrap";
      refreshName = "zann-delivery-${name}-refresh";
      targetName = lib.removeSuffix ".service" profile.targetUnit;
      bootstrapScript = deliveryScript name profile false;
      refreshScript = deliveryScript name profile true;
    in
    {
      services = {
        ${bootstrapName} = mkMerge [
          (hardenedService name profile bootstrapScript)
          { serviceConfig.RemainAfterExit = true; }
        ];
        ${refreshName} = hardenedService name profile refreshScript;
        ${targetName} = {
          requires = [ "${bootstrapName}.service" ];
          after = [ "${bootstrapName}.service" ];
        };
      };
      timers = lib.optionalAttrs (profile.refreshInterval != null) {
        ${refreshName} = {
          description = "Refresh Zann delivery profile ${name}";
          wantedBy = [ "timers.target" ];
          timerConfig = {
            OnBootSec = "5m";
            OnUnitActiveSec = profile.refreshInterval;
            RandomizedDelaySec = profile.randomizedDelaySec;
            Persistent = true;
            Unit = "${refreshName}.service";
          };
        };
      };
      tmpfilesRules = [
        "d /run/systemd/system/${profile.targetUnit}.d 0755 root root -"
      ];
    };

  profiles = lib.attrValues cfg.profiles;
  profileConfigs = lib.mapAttrsToList profileConfig cfg.profiles;
  credentialBindings = lib.concatMap (
    profile:
    map (target: "${profile.targetUnit}:${profile.credentialPrefix}_${target}") (
      lib.attrNames profile.secrets
    )
  ) profiles;
  expectedDropins =
    if cfg.enable then
      lib.mapAttrsToList (
        name: profile: "/run/systemd/system/${profile.targetUnit}.d/50-zann-delivery-${name}.conf"
      ) cfg.profiles
    else
      [ ];
in
{
  options.services.zann.delivery = {
    enable = mkEnableOption "generation-atomic Zann machine-secret delivery";

    package = mkOption {
      type = types.package;
      description = "Zann CLI package used by delivery units.";
    };

    profiles = mkOption {
      type = types.attrsOf profileType;
      default = { };
      description = "Declarative runtime delivery profiles.";
    };
  };

  config = mkMerge [
    {
      system.activationScripts.zannDeliveryDropinsCleanup.text = ''
        while IFS= read -r -d "" dropin; do
          keep=false
          for expected in ${lib.concatMapStringsSep " " lib.escapeShellArg expectedDropins}; do
            if [ "$dropin" = "$expected" ]; then
              keep=true
              break
            fi
          done
          if [ "$keep" = false ]; then
            ${pkgs.coreutils}/bin/rm -f -- "$dropin"
          fi
        done < <(${pkgs.findutils}/bin/find /run/systemd/system \
          -type f -path "*.service.d/50-zann-delivery-*.conf" -print0 2>/dev/null || true)
      '';
    }
    (mkIf cfg.enable {
      assertions = [
        {
          assertion = cfg.profiles != { };
          message = "services.zann.delivery requires at least one profile";
        }
        {
          assertion = lib.all safeProfileName (lib.attrNames cfg.profiles);
          message = "Zann delivery profile names must match [A-Za-z0-9][A-Za-z0-9_-]*";
        }
        {
          assertion = lib.all (
            profile:
            safeUnitName profile.targetUnit
            && safeCredentialName profile.credentialPrefix
            && builtins.stringLength profile.credentialPrefix <= 127
          ) profiles;
          message = "Zann delivery target units or credential prefixes are invalid";
        }
        {
          assertion = lib.all (
            profile:
            builtins.length (lib.attrNames profile.secrets) >= 1
            && builtins.length (lib.attrNames profile.secrets) <= 64
            && lib.all (
              target:
              safeCredentialName target && builtins.stringLength "${profile.credentialPrefix}_${target}" <= 255
            ) (lib.attrNames profile.secrets)
          ) profiles;
          message = "Zann systemd delivery requires 1-64 flat, valid credential filenames";
        }
        {
          assertion = lib.all (profile: lib.hasPrefix "/run/" profile.tokenFile) profiles;
          message = "Zann service-account tokenFile must be an absolute runtime path below /run";
        }
        {
          assertion = lib.all (
            profile: profile.allowInsecure || lib.hasPrefix "https://" profile.serverUrl
          ) profiles;
          message = "Zann delivery serverUrl must use https:// unless allowInsecure is explicit";
        }
        {
          assertion = builtins.length (lib.unique credentialBindings) == builtins.length credentialBindings;
          message = "Zann delivery profiles expose duplicate credential IDs to one target unit";
        }
      ];
      systemd = {
        services = mkMerge (map (profile: profile.services) profileConfigs);
        timers = mkMerge (map (profile: profile.timers) profileConfigs);
        tmpfiles.rules = lib.concatMap (profile: profile.tmpfilesRules) profileConfigs;
      };
    })
  ];
}
