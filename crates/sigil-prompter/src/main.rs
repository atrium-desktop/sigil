use clap::Parser;
use iris::{Application, Config};
use lens::{Frame, Input, Style, TextBuf};
use sigil_client::SigilSyncClient;

/// Interactive graphical credential prompter for Sigil vault.
#[derive(Parser, Debug)]
#[command(
    name = "sigil-prompter",
    author,
    version,
    about = "Interactive graphical credential prompter for Sigil vault"
)]
struct Cli {}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _cli = Cli::parse();

    let mut state = PrompterState::new();
    let config = Config::new("Vault Unlock")?
        .app_id("org.sigil.Prompter")?
        .size(420, 260);

    Application::run(
        config,
        move |frame, input| state.build(frame, input),
        None::<fn(iris::PaintHost)>,
    )?;

    Ok(())
}

struct PrompterState {
    password: TextBuf,
    error_message: Option<&'static str>,
}

impl PrompterState {
    fn new() -> Self {
        Self {
            password: TextBuf::new(256, ""),
            error_message: None,
        }
    }

    fn submit(&mut self) {
        let text = self.password.as_str();
        let pwd = text.trim();
        if pwd.is_empty() {
            self.error_message = Some("Password cannot be empty.");
        } else {
            let res = send_password(pwd);
            // Immediately wipe password from UI memory buffer with compiler fence
            self.password.set("");
            std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
            match res {
                Ok(_) => {
                    iris::window_close();
                }
                Err(UnlockError::Desynced) => {
                    self.error_message =
                        Some("Vault desynchronized! Run 'sigil recover' in terminal to sync.");
                }
                Err(_) => {
                    self.error_message = Some("Incorrect password. Please try again.");
                }
            }
        }
    }

    fn build(&mut self, frame: &mut Frame, input: &Input) {
        let raw = input.as_raw();
        for ev in &raw.keys[..raw.key_count as usize] {
            if !ev.pressed {
                continue;
            }
            if ev.key == lens::key::ESCAPE {
                iris::window_close();
                return;
            }
            if ev.key == lens::key::RETURN {
                self.submit();
                return;
            }
        }

        let mut trigger_submit = false;
        let mut trigger_cancel = false;

        frame
            .col()
            .pad(24.0)
            .gap(12.0)
            .items_center()
            .show(|frame| {
                frame.label_sized("Enter Vault Password", 18.0);

                let muted = frame.theme().fg().with_alpha(160);
                frame.push_style(Style::new().with_fg(muted));
                frame.label("Please provide the master password to continue.");
                frame.pop_style();

                frame.spacer(4.0);

                if frame.textfield_password("##pwd", &mut self.password, "Master Password")
                    && self.error_message.is_some()
                {
                    self.error_message = None;
                }

                if let Some(err) = self.error_message {
                    let err_color = frame.theme().error();
                    frame.push_style(Style::new().with_fg(err_color));
                    frame.label_sized(err, 12.0);
                    frame.pop_style();
                } else {
                    frame.spacer(14.0);
                }

                frame.spacer(4.0);

                frame.row().gap(16.0).items_center().show(|frame| {
                    if frame.button_subtle("Cancel") {
                        trigger_cancel = true;
                    }
                    if frame.button_primary("Unlock") {
                        trigger_submit = true;
                    }
                });
            });

        if trigger_cancel {
            iris::window_close();
        } else if trigger_submit {
            self.submit();
        }
    }
}

impl Drop for PrompterState {
    fn drop(&mut self) {
        self.password.set("");
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

enum UnlockError {
    IncorrectPassword,
    Desynced,
}

fn send_password(password: &str) -> Result<(), UnlockError> {
    let client = SigilSyncClient::connect_default();
    match client.unlock_with_password(password) {
        Ok(_) => Ok(()),
        Err(sigil_client::ClientError::Desynced) => Err(UnlockError::Desynced),
        Err(_) => Err(UnlockError::IncorrectPassword),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prompter_state_validation() {
        let mut state = PrompterState::new();
        assert_eq!(state.error_message, None);

        // Empty password triggers error
        state.submit();
        assert_eq!(state.error_message, Some("Password cannot be empty."));

        // Whitespace only also triggers error
        state.password = TextBuf::new(256, "   ");
        state.submit();
        assert_eq!(state.error_message, Some("Password cannot be empty."));
    }
}
