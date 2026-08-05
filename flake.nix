{
  description = "Zann";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
  };

  outputs = { self, nixpkgs, rust-overlay }:
    let
      system = "x86_64-linux";
      pkgsFor = s: import nixpkgs {
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
      packageSystems = [ "x86_64-linux" "aarch64-linux" ];

      zannCliFor = s: let
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
          cargoBuildFlags = [ "--bin" "zann" ];

          nativeBuildInputs = [ p.pkg-config ];
          buildInputs = with p; [
            openssl
            dbus
            libsecret
          ];

          meta.mainProgram = "zann";
        };
    in
    {
      packages = nixpkgs.lib.genAttrs packageSystems (s: rec {
        zann-cli = zannCliFor s;
        default = zann-cli;
      });

      devShells.${system} = {
        default = pkgs.mkShell {
          packages = with pkgs; [
            rustToolchain
            k6
            pkg-config
            openssl
            jemalloc
            llvm
            qt6.qtbase
            qt6.qtdeclarative
            qt6.qtsvg
            kdePackages.kirigami
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
            pkgs.qt6.qtbase
            pkgs.qt6.qtdeclarative
            pkgs.qt6.qtsvg
            pkgs.kdePackages.kirigami
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
