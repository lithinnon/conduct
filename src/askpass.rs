use crate::notify;
use crate::proc::ElevationContext;
use std::io::{self, IsTerminal, Write};
use std::process::Command;
use zeroize::Zeroizing;

#[derive(Debug, Clone)]
pub struct AskpassOptions {
    /// Custom prompt text provided by caller (e.g. sudo or ssh)
    pub prompt: Option<String>,
    /// Inspect a specific PID instead of parent process
    pub target_pid: Option<u32>,
    /// Whether to send desktop D-Bus notification
    pub send_notification: bool,
    /// Whether to print the terminal context banner
    pub show_banner: bool,
}

impl Default for AskpassOptions {
    fn default() -> Self {
        Self {
            prompt: None,
            target_pid: None,
            send_notification: true,
            show_banner: true,
        }
    }
}

/// Abstract password reader to facilitate hermetic testing and environment-adaptive prompting.
pub trait PasswordReader {
    fn read_password(&self, prompt: &str) -> io::Result<Zeroizing<String>>;
}

/// Standard password reader that attempts TTY, GUI dialog, or stdin in order.
pub struct SystemPasswordReader;

impl PasswordReader for SystemPasswordReader {
    fn read_password(&self, prompt: &str) -> io::Result<Zeroizing<String>> {
        let has_display = std::env::var_os("WAYLAND_DISPLAY").is_some()
            || std::env::var_os("DISPLAY").is_some();
        let stdin_is_tty = io::stdin().is_terminal();

        // 1. In graphical sessions, prioritize GUI dialog (ksshaskpass, kdialog, zenity)
        // especially when stdin is not a terminal (e.g. spawned by subagents or background harness).
        // This prevents blocking on a hidden /dev/tty where the user cannot interact.
        if has_display && (!stdin_is_tty || std::env::var_os("SUDO_ASKPASS").is_some() || std::env::var_os("SSH_ASKPASS").is_some()) {
            if let Some(pass) = try_gui_askpass(prompt) {
                return Ok(pass);
            }
        }

        // 2. If stdin is an interactive terminal, prompt on /dev/tty via rpassword
        if stdin_is_tty {
            if let Ok(pass) = rpassword::prompt_password(prompt) {
                return Ok(Zeroizing::new(pass));
            }
        }

        // 3. Fallback to GUI if display server is present
        if has_display {
            if let Some(pass) = try_gui_askpass(prompt) {
                return Ok(pass);
            }
        }

        // 4. Fallback to /dev/tty if available
        if let Ok(pass) = rpassword::prompt_password(prompt) {
            return Ok(Zeroizing::new(pass));
        }

        // 5. Fallback to piped standard input
        if !stdin_is_tty {
            let mut pass = String::new();
            io::stdin().read_line(&mut pass)?;
            let trimmed = pass.trim_end_matches(['\r', '\n']).to_string();
            return Ok(Zeroizing::new(trimmed));
        }

        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "No interactive GUI prompt, TTY, or stdin available to read password",
        ))
    }
}

/// Fallback to graphical askpass (kdialog, zenity) if available and running under Wayland/X11.
fn try_gui_askpass(prompt: &str) -> Option<Zeroizing<String>> {
    // Only attempt GUI dialog if a display server is configured
    if std::env::var_os("WAYLAND_DISPLAY").is_none() && std::env::var_os("DISPLAY").is_none() {
        return None;
    }

    // Try kdialog
    if let Ok(output) = Command::new("kdialog")
        .args(["--title", "conduct", "--password", prompt])
        .output()
    {
        if output.status.success() {
            let pass = String::from_utf8_lossy(&output.stdout)
                .trim_end_matches(['\r', '\n'])
                .to_string();
            return Some(Zeroizing::new(pass));
        }
    }

    // Try zenity
    if let Ok(output) = Command::new("zenity")
        .args([
            "--title=conduct",
            "--password",
            &format!("--text={}", prompt),
        ])
        .output()
    {
        if output.status.success() {
            let pass = String::from_utf8_lossy(&output.stdout)
                .trim_end_matches(['\r', '\n'])
                .to_string();
            return Some(Zeroizing::new(pass));
        }
    }

    // Try ksshaskpass
    if let Ok(output) = Command::new("ksshaskpass")
        .arg(prompt)
        .output()
    {
        if output.status.success() {
            let pass = String::from_utf8_lossy(&output.stdout)
                .trim_end_matches(['\r', '\n'])
                .to_string();
            return Some(Zeroizing::new(pass));
        }
    }

    None
}

/// Core orchestrator for the askpass flow.
pub fn run_askpass(options: AskpassOptions) -> io::Result<()> {
    let reader = SystemPasswordReader;
    let mut stdout = io::stdout();
    run_askpass_with(&options, &reader, &mut stdout)
}

/// Internal pipeline supporting dependency injection for testing.
pub fn run_askpass_with<R: PasswordReader, W: Write>(
    options: &AskpassOptions,
    reader: &R,
    writer: &mut W,
) -> io::Result<()> {
    // 1. Resolve context
    let context = match options.target_pid {
        Some(pid) => ElevationContext::inspect_pid(pid).ok(),
        None => ElevationContext::inspect_current_caller().ok(),
    };

    // 2. Desktop notification
    if options.send_notification {
        if let Some(ctx) = &context {
            if let Err(e) = notify::send_elevation_notification(ctx) {
                // Non-fatal warning so askpass never breaks if notification daemon is absent
                eprintln!("conduct: notice: desktop notification unavailable ({})", e);
            }
        }
    }

    // 3. Print terminal banner if enabled and stderr is a terminal
    if options.show_banner && io::stderr().is_terminal() {
        if let Some(ctx) = &context {
            eprintln!("{}", ctx.format_terminal_banner());
        }
    }

    // 4. Prompt string
    let prompt = options.prompt.as_deref().unwrap_or("[conduct] Password: ");

    // 5. Read password and wrap in Zeroizing
    let password = reader.read_password(prompt)?;

    // 6. Write password to stdout followed by newline and flush
    writer.write_all(password.as_bytes())?;
    writer.write_all(b"\n")?;
    writer.flush()?;

    // password dropped and zeroized here
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockPasswordReader {
        password: String,
    }

    impl PasswordReader for MockPasswordReader {
        fn read_password(&self, _prompt: &str) -> io::Result<Zeroizing<String>> {
            Ok(Zeroizing::new(self.password.clone()))
        }
    }

    #[test]
    fn test_askpass_flow_success() {
        let reader = MockPasswordReader {
            password: "super_secret_password".to_string(),
        };
        let mut output = Vec::new();
        let options = AskpassOptions {
            prompt: Some("Enter password: ".to_string()),
            target_pid: None,
            send_notification: false,
            show_banner: false,
        };

        run_askpass_with(&options, &reader, &mut output).unwrap();

        assert_eq!(output, b"super_secret_password\n");
    }

    #[test]
    fn test_zeroizing_behavior() {
        use zeroize::Zeroize;
        let mut secret = Zeroizing::new("temporary_key_data".to_string());
        assert_eq!(&*secret, "temporary_key_data");
        secret.zeroize();
        // Zeroize for String clears the buffer and truncates to length 0
        assert!(secret.is_empty());

        let mut byte_secret = Zeroizing::new([1u8, 2, 3, 4]);
        byte_secret.zeroize();
        assert_eq!(*byte_secret, [0u8, 0, 0, 0]);
    }
}
