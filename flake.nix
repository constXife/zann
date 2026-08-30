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
      # Без этого cargo протекал из глобального профиля пользователя,
      # и проект собирался версией, отличной от rust-toolchain.toml.
      toolchainFor = p: p.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
      rustToolchain = toolchainFor pkgs;

      # zann-cli ставится и на десктоп, и на aarch64-хосты, поэтому пакет
      # собирается под обе архитектуры. devShell остаётся x86_64-only —
      # он тянет Qt и WebKit, которые на aarch64 никому не нужны.
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
          # Не cargoHash: он требует ручного обновления при каждом изменении
          # зависимостей. Cargo.lock не содержит git-источников, поэтому
          # вендоринг выводится из него напрямую.
          cargoLock.lockFile = ./Cargo.lock;
          cargoBuildFlags = [
            "--bin"
            "zann"
          ];

          nativeBuildInputs = [ p.pkg-config ];
          buildInputs = with p; [
            openssl
            dbus
            libsecret
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

          meta.mainProgram = "zann-server";
        };

      # apps/cosmic живёт вне воркспейса и собирается свежим stable, а не пином
      # из rust-toolchain.toml: rust-version у libcosmic выше.
      zannCosmic =
        let
          toolchain = pkgs.rust-bin.stable.latest.default;
          rustPlatform = pkgs.makeRustPlatform {
            cargo = toolchain;
            rustc = toolchain;
          };
          # Библиотеки, которые грузятся через dlopen и потому не попадают в
          # rpath: без них приложение падает на старте с NoWaylandLib.
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
          # libcosmic держит iced git-подмодулем, а хешированный fetchgit
          # подмодули не выкачивает — крейты из iced/ тогда не находятся.
          # Submodules умеет только ветка allowBuiltinFetchGit, она же
          # избавляет от одиннадцати outputHashes. Цена — fetch на этапе
          # вычисления вместо content-addressed выборки.
          cargoLock = {
            lockFile = ./apps/cosmic/Cargo.lock;
            allowBuiltinFetchGit = true;
          };

          # И пример seed_demo_vault, и tests/flows.rs создают записи через
          # debug_create_kv_item, который в zann-ffi объявлен под
          # #[cfg(debug_assertions)] и в release не существует. Поэтому пакет
          # собирает только бинарь и не гоняет тесты — их место в debug CI и
          # `just cosmic-test`.
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
              # zann-ffi тянет zann-keystore, а тот hidapi для FIDO2-ключей;
              # его C-часть требует libudev с заголовками.
              udev
            ]
            ++ runtimeLibs;

          # Иконки лежат у Tauri-приложения: логотип у продукта один.
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
          # COSMIC-клиент только под x86_64: libcosmic на aarch64 никто не проверял.
          zann-cosmic = zannCosmic;
        }
      );

      devShells.${system} = {
        default = pkgs.mkShell {
          packages = with pkgs; [
            rustToolchain
            k6
            pkg-config
            openssl
            # hidapi (через ctap-hid-fido2) собирает C-часть и требует libudev
            # с заголовками; без него FIDO2-бэкенд кейстора не компилируется.
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
        };

        # apps/cosmic живёт вне воркспейса и тянет libcosmic, чей rust-version
        # опережает пин из rust-toolchain.toml. Отдельный шелл со свежим stable
        # не трогает сборку остального репозитория.
        cosmic = pkgs.mkShell {
          packages = with pkgs; [
            rust-bin.stable.latest.default
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
        };
      };
    };
}
