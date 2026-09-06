use clap::Parser;
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
        if let Some(ref path) = self.socket_path {
            return path.clone();
        }
        let runtime_dir = std::env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/tmp".into());
        PathBuf::from(runtime_dir).join("sigil/native.sock")
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
}
