#[cfg(unix)]
use std::io::Read;
use std::io::{self, Write};

use patronus_security_scanner::error::{Result, ScannerError};

struct Action {
    label: &'static str,
    command: &'static str,
    /// Prompt for the trailing target argument, with an optional default.
    target: Option<(&'static str, Option<&'static str>)>,
}

const ACTIONS: [Action; 7] = [
    Action {
        label: "Scan this repository",
        command: "scan repo",
        target: Some(("Repository path", Some("."))),
    },
    Action {
        label: "Scan a file",
        command: "scan file",
        target: Some(("File path", None)),
    },
    Action {
        label: "Scan a directory",
        command: "scan directory",
        target: Some(("Directory path", None)),
    },
    Action {
        label: "Scan a URL",
        command: "scan url",
        target: Some(("HTTPS URL", None)),
    },
    Action {
        label: "View setup status",
        command: "onboarding --status",
        target: None,
    },
    Action {
        label: "Open dashboard",
        command: "dashboard",
        target: None,
    },
    Action {
        label: "Run onboarding",
        command: "onboarding",
        target: None,
    },
];

pub fn choose() -> Result<Option<Vec<String>>> {
    let Some(action) = select()?.map(|index| &ACTIONS[index]) else {
        return Ok(None);
    };
    print!(
        "\x1b[H\x1b[2J\n  Patronus Security / {}\n  ─────────────────────────────────────────\n\n",
        action.label
    );
    io::stdout().flush().map_err(output_error)?;
    let mut args = action
        .command
        .split_whitespace()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if let Some((prompt, default)) = action.target {
        match default {
            Some(default) => print!("{prompt} [{default}]: "),
            None => print!("{prompt}: "),
        }
        io::stdout().flush().map_err(output_error)?;
        let mut value = String::new();
        if io::stdin().read_line(&mut value).map_err(output_error)? == 0 {
            return Ok(None);
        }
        let Some(value) = Some(value.trim()).filter(|v| !v.is_empty()).or(default) else {
            return Ok(None);
        };
        args.push(value.to_owned());
    }
    Ok(Some(args))
}

/// Without raw mode input arrives line by line, so read a whole line and parse it.
#[cfg(not(unix))]
fn select() -> Result<Option<usize>> {
    loop {
        draw(0)?;
        let mut line = String::new();
        if io::stdin().read_line(&mut line).map_err(output_error)? == 0 {
            return Ok(None);
        }
        match line.trim() {
            "" => return Ok(Some(0)),
            "q" => return Ok(None),
            value => {
                if let Some(index) = value
                    .parse::<usize>()
                    .ok()
                    .filter(|n| (1..=ACTIONS.len()).contains(n))
                {
                    return Ok(Some(index - 1));
                }
            }
        }
    }
}

#[cfg(unix)]
fn select() -> Result<Option<usize>> {
    let _terminal = RawTerminal::enter()?;
    let mut selected = 0;
    loop {
        draw(selected)?;
        let mut key = [0];
        io::stdin().read_exact(&mut key).map_err(output_error)?;
        match key[0] {
            b'\r' | b'\n' => return Ok(Some(selected)),
            b'q' | 3 => return Ok(None),
            digit @ b'1'..=b'9' if usize::from(digit - b'1') < ACTIONS.len() => {
                return Ok(Some(usize::from(digit - b'1')))
            }
            27 => {
                if let Some(b'[') = escape_byte()? {
                    selected = match escape_byte()? {
                        Some(b'A') => (selected + ACTIONS.len() - 1) % ACTIONS.len(),
                        Some(b'B') => (selected + 1) % ACTIONS.len(),
                        _ => selected,
                    };
                } else {
                    return Ok(None);
                }
            }
            _ => {}
        }
    }
}

#[cfg(unix)]
fn escape_byte() -> Result<Option<u8>> {
    let mut descriptor = libc::pollfd {
        fd: libc::STDIN_FILENO,
        events: libc::POLLIN,
        revents: 0,
    };
    let ready = unsafe { libc::poll(&mut descriptor, 1, 75) };
    if ready < 0 {
        return Err(output_error(io::Error::last_os_error()));
    }
    if ready == 0 {
        return Ok(None);
    }
    let mut byte = [0];
    io::stdin().read_exact(&mut byte).map_err(output_error)?;
    Ok(Some(byte[0]))
}

fn draw(selected: usize) -> Result<()> {
    let mut out = io::stdout().lock();
    write!(
        out,
        "\x1b[H\x1b[2J\n  Patronus Security\n  ─────────────────────────────────────────\n\n"
    )
    .map_err(output_error)?;
    for (index, action) in ACTIONS.iter().enumerate() {
        let marker = if index == selected { "❯" } else { " " };
        writeln!(out, "  {marker} {}. {}", index + 1, action.label).map_err(output_error)?;
    }
    let count = ACTIONS.len();
    let controls = if cfg!(unix) {
        format!("↑↓ select · Enter run · 1–{count} quick select · Esc/q quit")
    } else {
        format!("Type 1–{count} then Enter · Enter runs 1 · q quit")
    };
    write!(out, "\n  {controls}\n").map_err(output_error)?;
    out.flush().map_err(output_error)
}

fn output_error(error: io::Error) -> ScannerError {
    ScannerError::Output(error.to_string())
}

#[cfg(unix)]
struct RawTerminal {
    original: libc::termios,
}

#[cfg(unix)]
impl RawTerminal {
    fn enter() -> Result<Self> {
        use std::mem::MaybeUninit;
        let mut original = MaybeUninit::<libc::termios>::uninit();
        if unsafe { libc::tcgetattr(libc::STDIN_FILENO, original.as_mut_ptr()) } != 0 {
            return Err(output_error(io::Error::last_os_error()));
        }
        let original = unsafe { original.assume_init() };
        let mut raw = original;
        raw.c_lflag &= !(libc::ICANON | libc::ECHO | libc::ISIG);
        raw.c_cc[libc::VMIN] = 1;
        raw.c_cc[libc::VTIME] = 0;
        if unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &raw) } != 0 {
            return Err(output_error(io::Error::last_os_error()));
        }
        print!("\x1b[?25l");
        if let Err(error) = io::stdout().flush() {
            unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &original) };
            return Err(output_error(error));
        }
        Ok(Self { original })
    }
}

#[cfg(unix)]
impl Drop for RawTerminal {
    fn drop(&mut self) {
        unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &self.original) };
        print!("\x1b[?25h");
        let _ = io::stdout().flush();
    }
}
