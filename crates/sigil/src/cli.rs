use clap::{Parser, Subcommand};
use directories::ProjectDirs;
use std::path::PathBuf;

/// Desktop session credential infrastructure daemon.
///
/// Sigil is a memory-safe Secret Service implementation providing hardware-backed
/// security, zero-touch PAM provisioning, and a hardened native IPC protocol.
#[derive(Parser, Debug, Clone)]
#[command(
    name = "sigil",
    author,
    version,
    about = "Desktop session credential infrastructure daemon",
    long_about = None
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Custom path to vault data storage directory
    #[arg(
        short = 'd',
        long = "data-dir",
        env = "SIGIL_DATA_DIR",
        value_name = "DIR"
    )]
    pub data_dir: Option<PathBuf>,

    /// Custom path to the native IPC socket
    #[arg(
        short = 's',
        long = "socket-path",
        env = "SIGIL_SOCKET_PATH",
        value_name = "PATH"
    )]
    pub socket_path: Option<PathBuf>,

    /// Headless vault unlock password (for automated testing / CI)
    #[arg(
        long = "password",
        env = "SIGIL_PASSWORD",
        value_name = "PASSWORD",
        hide_env_values = true
    )]
    pub password: Option<String>,

    /// Read headless vault unlock password from a file
    #[arg(long = "password-file", value_name = "FILE")]
    pub password_file: Option<PathBuf>,

    /// Increase logging verbosity (-v for debug, -vv for trace)
    #[arg(short = 'v', long = "verbose", action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Suppress non-error log messages
    #[arg(short = 'q', long = "quiet", conflicts_with = "verbose")]
    pub quiet: bool,
}

#[derive(Subcommand, Debug, Clone)]
pub enum Commands {
    /// Query the status of the running Sigil credential daemon
    Status,
    /// Unlock the running Sigil credential daemon from terminal
    Unlock {
        /// Unlock password (if omitted, prompts interactively with echo disabled)
        #[arg(long = "password", env = "SIGIL_PASSWORD")]
        password: Option<String>,

        /// Read unlock password from file
        #[arg(long = "password-file", value_name = "FILE")]
        password_file: Option<PathBuf>,

        /// Unlock using an emergency recovery key
        #[arg(long = "recovery-key", value_name = "KEY")]
        recovery_key: Option<String>,
    },
    /// Lock the running Sigil credential daemon, immediately zeroizing memory
    Lock,
    /// Recover and re-synchronize a desynchronized vault with a new password
    Recover {
        /// Previous password or emergency recovery key
        #[arg(long = "recovery-secret", env = "SIGIL_RECOVERY_SECRET")]
        recovery_secret: Option<String>,

        /// New session login password to seal Slot 0
        #[arg(long = "new-password", env = "SIGIL_NEW_PASSWORD")]
        new_password: Option<String>,
    },
    /// Manage emergency recovery keys (Slot 1)
    RecoveryKey {
        #[command(subcommand)]
        action: RecoveryKeyAction,
    },
    /// Run diagnostic health checks on D-Bus, PAM, socket, and storage
    Doctor,
    /// Import credentials from a JSON or CSV file
    ImportCredentials {
        /// Path to the credential file (.json or .csv)
        #[arg(short = 'i', long = "input", value_name = "FILE")]
        input: PathBuf,

        /// Target collection ID (defaults to "login")
        #[arg(short = 'c', long = "collection", default_value = "login")]
        collection: String,

        /// Explicit format override: json or csv
        #[arg(long = "format", value_name = "FORMAT")]
        format: Option<String>,
    },
    /// Export the vault into an encrypted backup archive
    ExportVault {
        /// Path to write the encrypted backup archive
        #[arg(short = 'o', long = "output", value_name = "FILE")]
        output: PathBuf,

        /// Archive encryption password (defaults to vault unlock password if omitted)
        #[arg(long = "archive-password", env = "SIGIL_BACKUP_PASSWORD")]
        archive_password: Option<String>,
    },
    /// Import credentials from an encrypted backup archive
    ImportVault {
        /// Path to the encrypted backup archive
        #[arg(short = 'i', long = "input", value_name = "FILE")]
        input: PathBuf,

        /// Archive decryption password (defaults to vault unlock password if omitted)
        #[arg(long = "archive-password", env = "SIGIL_BACKUP_PASSWORD")]
        archive_password: Option<String>,
    },
}

#[derive(Subcommand, Debug, Clone)]
pub enum RecoveryKeyAction {
    /// Generate and enroll a new emergency recovery key into Slot 1
    Generate,
    /// Verify a recovery key against Slot 1
    Verify {
        #[arg(value_name = "KEY")]
        key: Option<String>,
    },
}

impl Cli {
    /// Resolves the vault storage directory with CLI override -> env var -> standard XDG fallback.
    pub fn resolve_data_dir(&self) -> PathBuf {
        if let Some(ref dir) = self.data_dir {
            return dir.clone();
        }
        if let Some(proj_dirs) = ProjectDirs::from("org", "freedesktop", "sigil") {
            proj_dirs.data_dir().to_path_buf()
        } else {
            PathBuf::from(".local/share/sigil")
        }
    }

    /// Resolves the native IPC socket path with CLI override -> env var -> standard XDG fallback.
    pub fn resolve_socket_path(&self) -> PathBuf {
        sigil_ipc::resolve_socket_path(self.socket_path.as_deref())
    }

    /// Configures the tracing subscriber based on CLI verbosity and environment.
    pub fn init_logging(&self) {
        use tracing_subscriber::{fmt, EnvFilter};

        let default_filter = if self.quiet {
            "error"
        } else {
            match self.verbose {
                0 => "info",
                1 => "debug",
                _ => "trace",
            }
        };

        let filter =
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_filter));

        let _ = fmt().with_env_filter(filter).try_init();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_version_flag() {
        let err = Cli::try_parse_from(["sigil", "--version"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayVersion);
        let out = err.to_string();
        assert!(out.contains(env!("CARGO_PKG_VERSION")));

        let err_short = Cli::try_parse_from(["sigil", "-V"]).unwrap_err();
        assert_eq!(err_short.kind(), clap::error::ErrorKind::DisplayVersion);
    }

    #[test]
    fn test_cli_help_flag() {
        let err = Cli::try_parse_from(["sigil", "--help"]).unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayHelp);
        let out = err.to_string();
        assert!(out.contains("--data-dir"));
        assert!(out.contains("--socket-path"));
        assert!(out.contains("--password"));
        assert!(out.contains("--password-file"));
    }

    #[test]
    fn test_cli_data_dir_and_socket_path_args() {
        let cli = Cli::try_parse_from([
            "sigil",
            "--data-dir",
            "/custom/data",
            "--socket-path",
            "/custom/socket.sock",
        ])
        .expect("should parse custom paths");

        assert_eq!(cli.resolve_data_dir(), PathBuf::from("/custom/data"));
        assert_eq!(
            cli.resolve_socket_path(),
            PathBuf::from("/custom/socket.sock")
        );
    }

    #[test]
    fn test_cli_rejects_unknown_arguments() {
        let res = Cli::try_parse_from(["sigil", "--unknown-option"]);
        assert!(res.is_err());
        let err = res.unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::UnknownArgument);
    }

    #[test]
    fn test_cli_verbosity_levels() {
        let cli0 = Cli::try_parse_from(["sigil"]).unwrap();
        assert_eq!(cli0.verbose, 0);
        assert!(!cli0.quiet);

        let cli1 = Cli::try_parse_from(["sigil", "-v"]).unwrap();
        assert_eq!(cli1.verbose, 1);

        let cli2 = Cli::try_parse_from(["sigil", "-vv"]).unwrap();
        assert_eq!(cli2.verbose, 2);

        let cliq = Cli::try_parse_from(["sigil", "--quiet"]).unwrap();
        assert!(cliq.quiet);

        // --quiet and -v conflict
        assert!(Cli::try_parse_from(["sigil", "-v", "--quiet"]).is_err());
    }

    #[test]
    fn test_cli_subcommands_export_and_import() {
        let export_cli = Cli::try_parse_from([
            "sigil",
            "export-vault",
            "--output",
            "/tmp/backup.sigil",
            "--archive-password",
            "backup-secret",
        ])
        .unwrap();

        match export_cli.command {
            Some(Commands::ExportVault {
                output,
                archive_password,
            }) => {
                assert_eq!(output, PathBuf::from("/tmp/backup.sigil"));
                assert_eq!(archive_password.as_deref(), Some("backup-secret"));
            }
            _ => panic!("Expected ExportVault subcommand"),
        }

        let import_cli = Cli::try_parse_from([
            "sigil",
            "import-vault",
            "--input",
            "/tmp/backup.sigil",
            "--archive-password",
            "backup-secret",
        ])
        .unwrap();

        match import_cli.command {
            Some(Commands::ImportVault {
                input,
                archive_password,
            }) => {
                assert_eq!(input, PathBuf::from("/tmp/backup.sigil"));
                assert_eq!(archive_password.as_deref(), Some("backup-secret"));
            }
            _ => panic!("Expected ImportVault subcommand"),
        }

        // Test status and lock
        let status_cli = Cli::try_parse_from(["sigil", "status"]).unwrap();
        assert!(matches!(status_cli.command, Some(Commands::Status)));

        let lock_cli = Cli::try_parse_from(["sigil", "lock"]).unwrap();
        assert!(matches!(lock_cli.command, Some(Commands::Lock)));

        // Test doctor
        let doc_cli = Cli::try_parse_from(["sigil", "doctor"]).unwrap();
        assert!(matches!(doc_cli.command, Some(Commands::Doctor)));

        // Test unlock with recovery-key
        let unlock_cli =
            Cli::try_parse_from(["sigil", "unlock", "--recovery-key", "SIGIL-RKEY-123"]).unwrap();
        match unlock_cli.command {
            Some(Commands::Unlock { recovery_key, .. }) => {
                assert_eq!(recovery_key.as_deref(), Some("SIGIL-RKEY-123"));
            }
            _ => panic!("Expected Unlock subcommand"),
        }

        // Test recovery-key generate
        let rkey_cli = Cli::try_parse_from(["sigil", "recovery-key", "generate"]).unwrap();
        match rkey_cli.command {
            Some(Commands::RecoveryKey {
                action: RecoveryKeyAction::Generate,
            }) => {}
            _ => panic!("Expected RecoveryKey Generate"),
        }

        // Test recover
        let recover_cli = Cli::try_parse_from([
            "sigil",
            "recover",
            "--recovery-secret",
            "old-pass-or-key",
            "--new-password",
            "new-system-pass",
        ])
        .unwrap();
        match recover_cli.command {
            Some(Commands::Recover {
                recovery_secret,
                new_password,
            }) => {
                assert_eq!(recovery_secret.as_deref(), Some("old-pass-or-key"));
                assert_eq!(new_password.as_deref(), Some("new-system-pass"));
            }
            _ => panic!("Expected Recover subcommand"),
        }

        // Test import-credentials
        let import_cred_cli = Cli::try_parse_from([
            "sigil",
            "import-credentials",
            "--input",
            "/tmp/creds.json",
            "--collection",
            "work",
        ])
        .unwrap();
        match import_cred_cli.command {
            Some(Commands::ImportCredentials {
                input,
                collection,
                format,
            }) => {
                assert_eq!(input, PathBuf::from("/tmp/creds.json"));
                assert_eq!(collection, "work");
                assert_eq!(format, None);
            }
            _ => panic!("Expected ImportCredentials"),
        }
    }
}
