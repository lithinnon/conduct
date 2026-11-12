{
  description = "Context-aware, notification-driven askpass and privilege orchestrator for sudo, SSH, and Polkit";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      supportedSystems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;
      pkgsFor = system: import nixpkgs { inherit system; };
    in
    {
      packages = forAllSystems (system:
        let
          pkgs = pkgsFor system;
        in
        {
          conduct = pkgs.rustPlatform.buildRustPackage {
            pname = "conduct";
            version = "0.1.0";
            src = ./.;
            cargoLock = {
              lockFile = ./Cargo.lock;
            };
            nativeBuildInputs = with pkgs; [
              pkg-config
            ];
            buildInputs = with pkgs; [
              dbus
            ];
            meta = with pkgs.lib; {
              description = "Context-aware, notification-driven askpass and privilege orchestrator";
              homepage = "https://github.com/lithinnon/conduct";
              license = licenses.gpl3Plus;
              maintainers = [ ];
              mainProgram = "conduct";
            };
          };
          default = self.packages.${system}.conduct;
        }
      );

      devShells = forAllSystems (system:
        let
          pkgs = pkgsFor system;
        in
        {
          default = pkgs.mkShell {
            nativeBuildInputs = with pkgs; [
              pkg-config
            ];
            buildInputs = with pkgs; [
              cargo
              rustc
              clippy
              rustfmt
              rust-analyzer
              dbus
            ];
          };
        }
      );

      nixosModules.default = { config, lib, pkgs, ... }:
        let
          cfg = config.programs.conduct;
        in
        {
          options.programs.conduct = {
            enable = lib.mkEnableOption "conduct askpass orchestrator";
            package = lib.mkOption {
              type = lib.types.package;
              default = self.packages.${pkgs.system}.default;
              description = "The conduct package to install.";
            };
            enableSudoAskpass = lib.mkOption {
              type = lib.types.bool;
              default = true;
              description = "Whether to configure conduct as SUDO_ASKPASS.";
            };
            enableSshAskpass = lib.mkOption {
              type = lib.types.bool;
              default = false;
              description = "Whether to configure conduct as SSH_ASKPASS.";
            };
            enableTouchDetector = lib.mkOption {
              type = lib.types.bool;
              default = true;
              description = "Whether to run conduct watch daemon in user session for YubiKey touch detection.";
            };
          };

          config = lib.mkIf cfg.enable {
            environment.systemPackages = [ cfg.package ];
            environment.variables = lib.mkMerge [
              (lib.mkIf cfg.enableSudoAskpass {
                SUDO_ASKPASS = lib.mkDefault "/run/current-system/sw/bin/conduct";
              })
            ];

            programs.ssh = lib.mkIf cfg.enableSshAskpass {
              enableAskPassword = lib.mkDefault true;
              askPassword = "/run/current-system/sw/bin/conduct";
            };

            systemd.user.services.conduct-watch = lib.mkIf cfg.enableTouchDetector {
              description = "Conduct YubiKey and PAM U2F touch detection daemon";
              wantedBy = [ "graphical-session.target" ];
              partOf = [ "graphical-session.target" ];
              serviceConfig = {
                ExecStart = "${cfg.package}/bin/conduct watch";
                Restart = "always";
                RestartSec = "2";
              };
            };
          };
        };

      homeManagerModules.default = { config, lib, pkgs, ... }:
        let
          cfg = config.programs.conduct;
        in
        {
          options.programs.conduct = {
            enable = lib.mkEnableOption "conduct askpass orchestrator";
            package = lib.mkOption {
              type = lib.types.package;
              default = self.packages.${pkgs.system}.default;
              description = "The conduct package to install.";
            };
            enableSudoAskpass = lib.mkOption {
              type = lib.types.bool;
              default = true;
              description = "Whether to configure conduct as SUDO_ASKPASS.";
            };
            enableSshAskpass = lib.mkOption {
              type = lib.types.bool;
              default = false;
              description = "Whether to configure conduct as SSH_ASKPASS.";
            };
            enableTouchDetector = lib.mkOption {
              type = lib.types.bool;
              default = true;
              description = "Whether to run conduct watch daemon in user session for YubiKey touch detection.";
            };
          };

          config = lib.mkIf cfg.enable {
            home.packages = [ cfg.package ];
            home.sessionVariables = lib.mkMerge [
              (lib.mkIf cfg.enableSudoAskpass {
                SUDO_ASKPASS = lib.mkDefault "${config.home.profileDirectory}/bin/conduct";
              })
              (lib.mkIf cfg.enableSshAskpass {
                SSH_ASKPASS = lib.mkDefault "${config.home.profileDirectory}/bin/conduct";
              })
            ];

            systemd.user.services.conduct-watch = lib.mkIf cfg.enableTouchDetector {
              Unit = {
                Description = "Conduct YubiKey and PAM U2F touch detection daemon";
                PartOf = [ "graphical-session.target" ];
              };
              Install = {
                WantedBy = [ "graphical-session.target" ];
              };
              Service = {
                ExecStart = "${cfg.package}/bin/conduct watch";
                Restart = "always";
                RestartSec = "2";
              };
            };
          };
        };
    };
}
