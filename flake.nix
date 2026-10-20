{
  description = "Zann";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs =
    {
      self,
      nixpkgs,
      rust-overlay,
    }:
    let
      system = "x86_64-linux";
      pkgsFor =
        s:
        import nixpkgs {
          system = s;
          overlays = [ (import rust-overlay) ];
        };
      pkgs = pkgsFor system;
      # Without this, cargo leaked in from the user's global profile and the
      # project was built with a version other than rust-toolchain.toml.
      toolchainFor = p: p.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
      rustToolchain = toolchainFor pkgs;

      # Since 1.90, rustc on x86_64-unknown-linux-gnu links with its bundled
      # rust-lld instead of ld.bfd, so the baseline is already fast. mold still
      # beats lld on large binaries (webkit, Qt and a heavy workspace here), but
      # the gain is tens of percent on the link step, not multiples on the
      # whole build. gcc 15 understands -fuse-ld=mold directly, so the shell
      # does not need clang.
      #
      # The flag is set through env rather than .cargo/config.toml: the linker
      # path then comes from the nix store and the shell stays hermetic, so
      # builds outside `nix develop` do not break on a missing mold.
      #
      # The variable is deliberately target-specific: RUSTFLAGS would also hit
      # cross targets (tauri android/ios), where mold does not work.
      moldEnv = {
        CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS = "-C link-arg=-fuse-ld=mold";
      };

      # zann-cli is installed on desktops and on aarch64 hosts, so the package
      # is built for both architectures. The devShell stays x86_64-only: it pulls
      # in Qt and WebKit, which nobody needs on aarch64.
      packageSystems = [
        "x86_64-linux"
        "aarch64-linux"
      ];

      zannCliFor =
        s:
        let
          p = pkgsFor s;
          toolchain = toolchainFor p;
          rustPlatform = p.makeRustPlatform {
            cargo = toolchain;
            rustc = toolchain;
          };
        in
        rustPlatform.buildRustPackage {
          pname = "zann-cli";
          version = "0.1.0";
          src = self;
          # Not cargoHash: it needs a manual update on every dependency change.
          # Cargo.lock has no git sources, so vendoring is derived from it directly.
          cargoLock.lockFile = ./Cargo.lock;
          cargoBuildFlags = [
            "--package"
            "zann-cli"
            "--bin"
            "zann"
          ];
          cargoTestFlags = [
            "--package"
            "zann-cli"
            "--bin"
            "zann"
          ];

          nativeBuildInputs = [ p.pkg-config ];
          buildInputs = with p; [
            openssl
            dbus
            libsecret
            udev
          ];

          meta.mainProgram = "zann";
        };

      zannServerFor =
        s:
        let
          p = pkgsFor s;
          toolchain = toolchainFor p;
          rustPlatform = p.makeRustPlatform {
            cargo = toolchain;
            rustc = toolchain;
          };
        in
        rustPlatform.buildRustPackage {
          pname = "zann-server";
          version = "0.1.0";
          src = self;
          cargoLock.lockFile = ./Cargo.lock;
          cargoBuildFlags = [
            "--package"
            "zann-server"
            "--bin"
            "zann-server"
          ];
          doCheck = false;

          nativeBuildInputs = [ p.pkg-config ];
          buildInputs = [ p.openssl ];

          meta.mainProgram = "zann-server";
        };

      # apps/cosmic lives outside the workspace and is built with the latest
      # stable rather than the rust-toolchain.toml pin: libcosmic's rust-version
      # is higher.
      zannCosmic =
        let
          toolchain = pkgs.rust-bin.stable.latest.default;
          rustPlatform = pkgs.makeRustPlatform {
            cargo = toolchain;
            rustc = toolchain;
          };
          # Libraries loaded through dlopen, which therefore never reach the rpath:
          # without them the app crashes on startup with NoWaylandLib.
          runtimeLibs = with pkgs; [
            libxkbcommon
            wayland
            vulkan-loader
            libGL
          ];
        in
        rustPlatform.buildRustPackage {
          pname = "zann-cosmic";
          version = "0.1.0-unstable-2026-08-05";
          src = self;
          cargoRoot = "apps/cosmic";
          buildAndTestSubdir = "apps/cosmic";
          # libcosmic keeps iced as a git submodule, and a hashed fetchgit does not
          # fetch submodules, so the crates under iced/ are not found. Only the
          # allowBuiltinFetchGit path handles submodules, and it also avoids eleven
          # outputHashes. The cost is a fetch at evaluation time instead of a
          # content-addressed fetch.
          cargoLock = {
            lockFile = ./apps/cosmic/Cargo.lock;
            allowBuiltinFetchGit = true;
          };

          # Both the seed_demo_vault example and tests/flows.rs create items through
          # debug_create_kv_item, which zann-ffi declares under
          # #[cfg(debug_assertions)], so it does not exist in release. The package
          # therefore builds only the binary and runs no tests; those belong in
          # debug CI and `just cosmic-test`.
          cargoBuildFlags = [
            "--bin"
            "zann-cosmic"
          ];
          doCheck = false;

          nativeBuildInputs = with pkgs; [
            pkg-config
            makeWrapper
          ];
          buildInputs =
            with pkgs;
            [
              openssl
              libxkbcommon
              wayland
              expat
              fontconfig
              freetype
              # zann-ffi pulls in zann-keystore, which uses hidapi for FIDO2 keys;
              # its C part needs libudev with headers.
              udev
            ]
            ++ runtimeLibs;

          # The icons live with the Tauri app: the product has a single logo.
          postInstall = ''
            install -Dm644 apps/cosmic/data/com.rlyeh.zann.Cosmic.desktop \
              $out/share/applications/com.rlyeh.zann.Cosmic.desktop
            for pair in 32:32x32 64:64x64 128:128x128 256:128x128@2x 512:icon; do
              size="''${pair%%:*}"; src="''${pair##*:}"
              install -Dm644 "apps/desktop/src-tauri/icons/''${src}.png" \
                "$out/share/icons/hicolor/''${size}x''${size}/apps/com.rlyeh.zann.Cosmic.png"
            done
            wrapProgram $out/bin/zann-cosmic \
              --prefix LD_LIBRARY_PATH : ${nixpkgs.lib.makeLibraryPath runtimeLibs}
          '';

          meta = {
            mainProgram = "zann-cosmic";
            description = "COSMIC-native zann client";
            license = nixpkgs.lib.licenses.mit;
            platforms = [ "x86_64-linux" ];
          };
        };
    in
    {
      nixosModules = {
        zann-delivery = { lib, pkgs, ... }: {
          imports = [ ./nix/modules/zann-delivery.nix ];
          services.zann.delivery.package =
            lib.mkDefault
              self.packages.${pkgs.stdenv.hostPlatform.system}.zann-cli;
        };
        default = self.nixosModules.zann-delivery;
      };

      checks.${system} = {
        zann-delivery-module = import ./nix/tests/zann-delivery-module.nix {
          inherit nixpkgs system;
          module = self.nixosModules.zann-delivery;
        };
        zann-delivery-vm = import ./nix/tests/zann-delivery-vm.nix {
          inherit pkgs;
          module = self.nixosModules.zann-delivery;
        };
        zann-delivery-real-server-vm = import ./nix/tests/zann-delivery-real-server-vm.nix {
          inherit pkgs;
          module = self.nixosModules.zann-delivery;
          zannCli = self.packages.${system}.zann-cli;
          zannServer = self.packages.${system}.zann-server;
        };
      };

      packages = nixpkgs.lib.genAttrs packageSystems (
        s:
        rec {
          zann-cli = zannCliFor s;
          zann-server = zannServerFor s;
          default = zann-cli;
        }
        // nixpkgs.lib.optionalAttrs (s == system) {
          # COSMIC client is x86_64-only: nobody has checked libcosmic on aarch64.
          zann-cosmic = zannCosmic;
        }
      );

      devShells.${system} = {
        default = pkgs.mkShell (moldEnv // {
          packages = with pkgs; [
            rustToolchain
            mold
            cargo-nextest
            cargo-sweep
            k6
            pkg-config
            openssl
            # hidapi (via ctap-hid-fido2) builds a C part and needs libudev with
            # headers; without it the keystore FIDO2 backend does not compile.
            udev
            jemalloc
            llvm
            libxkbcommon
            wayland
            wayland-protocols
            glib
            gtk3
            gdk-pixbuf
            pango
            cairo
            atk
            libsoup_3
            webkitgtk_4_1
            xorg.xvfb
            libayatana-appindicator
          ];
          LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath [
            pkgs.openssl
            pkgs.libxkbcommon
            pkgs.wayland
            pkgs.glib
            pkgs.gtk3
            pkgs.gdk-pixbuf
            pkgs.pango
            pkgs.cairo
            pkgs.atk
            pkgs.libsoup_3
            pkgs.webkitgtk_4_1
            pkgs.libayatana-appindicator
          ];
          OPENSSL_DIR = pkgs.openssl.dev;
          OPENSSL_LIB_DIR = "${pkgs.openssl.out}/lib";
          OPENSSL_INCLUDE_DIR = "${pkgs.openssl.dev}/include";
        });

        # apps/cosmic lives outside the workspace and pulls in libcosmic, whose
        # rust-version is ahead of the rust-toolchain.toml pin. A separate shell
        # with the latest stable leaves the rest of the repository's build alone.
        cosmic = pkgs.mkShell (moldEnv // {
          packages = with pkgs; [
            rust-bin.stable.latest.default
            mold
            cargo-nextest
            pkg-config
            openssl
            udev
            libxkbcommon
            wayland
            wayland-protocols
            expat
            fontconfig
            freetype
            libGL
            vulkan-loader
          ];
          LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath [
            pkgs.libxkbcommon
            pkgs.wayland
            pkgs.expat
            pkgs.fontconfig
            pkgs.freetype
            pkgs.libGL
            pkgs.vulkan-loader
          ];
          OPENSSL_DIR = pkgs.openssl.dev;
          OPENSSL_LIB_DIR = "${pkgs.openssl.out}/lib";
          OPENSSL_INCLUDE_DIR = "${pkgs.openssl.dev}/include";
        });
      };
    };
}
