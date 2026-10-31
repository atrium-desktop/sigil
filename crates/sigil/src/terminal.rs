use std::io::{self, BufRead, Write};
use zeroize::Zeroize;

/// RAII wrapper around a sensitive password string that zeroizes its memory upon drop.
pub struct PasswordGuard(String);

impl PasswordGuard {
    pub fn new(s: String) -> Self {
        Self(s)
    }

    #[allow(dead_code)]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn into_inner(mut self) -> String {
        std::mem::take(&mut self.0)
    }
}

impl Drop for PasswordGuard {
    fn drop(&mut self) {
        self.0.zeroize();
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

struct EchoGuard {
    termios: libc::termios,
    fd: i32,
    active: bool,
}

impl Drop for EchoGuard {
    fn drop(&mut self) {
        if self.active {
            unsafe {
                libc::tcsetattr(self.fd, libc::TCSANOW, &self.termios);
            }
        }
    }
}

/// Prompts the user on the terminal for a password with echo disabled and zeroization on drop.
pub fn read_password_prompt(prompt: &str) -> io::Result<PasswordGuard> {
    let fd = libc::STDIN_FILENO;
    let is_tty = unsafe { libc::isatty(fd) } == 1;

    let mut guard = if is_tty {
        let mut termios: libc::termios = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(fd, &mut termios) } != 0 {
            return Err(io::Error::last_os_error());
        }

        let original = termios;
        let mut no_echo = termios;
        no_echo.c_lflag &= !(libc::ECHO | libc::ECHONL);

        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &no_echo) } != 0 {
            return Err(io::Error::last_os_error());
        }

        EchoGuard {
            termios: original,
            fd,
            active: true,
        }
    } else {
        let dummy: libc::termios = unsafe { std::mem::zeroed() };
        EchoGuard {
            termios: dummy,
            fd,
            active: false,
        }
    };

    print!("{prompt}");
    io::stdout().flush()?;

    let mut line = String::new();
    let stdin = io::stdin();
    stdin.lock().read_line(&mut line)?;

    if guard.active {
        // Restore echo before newline so terminal behaves normally
        unsafe {
            libc::tcsetattr(guard.fd, libc::TCSANOW, &guard.termios);
        }
        guard.active = false;
        println!();
    }

    let trimmed = line.trim_end_matches(&['\r', '\n'][..]).to_string();
    line.zeroize();

    Ok(PasswordGuard::new(trimmed))
}
