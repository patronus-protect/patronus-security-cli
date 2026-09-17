use std::io::{self, Read, Write};

use patronus_security_scanner::error::{Result, ScannerError};

const ACTIONS: [(&str, &str); 7] = [
    ("Scan this repository", "scan repo"),
    ("Scan a file", "scan file"),
    ("Scan a directory", "scan directory"),
    ("Scan a URL", "scan url"),
    ("View setup status", "onboarding --status"),
    ("Open dashboard", "dashboard"),
    ("Run onboarding", "onboarding"),
];

pub fn choose() -> Result<Option<Vec<String>>> {
    let selection = select()?;
    let Some(index) = selection else {
        return Ok(None);
    };
    print!(
        "\x1b[H\x1b[2J\n  Patronus Security / {}\n  ─────────────────────────────────────────\n\n",
        ACTIONS[index].0
    );
    io::stdout().flush().map_err(output_error)?;
    let mut args = ACTIONS[index]
        .1
        .split_whitespace()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let prompt = match index {
        0 => Some("Repository path [.]"),
        1 => Some("File path"),
        2 => Some("Directory path"),
        3 => Some("HTTPS URL"),
        _ => None,
    };
    if let Some(prompt) = prompt {
        print!("{prompt}: ");
        io::stdout().flush().map_err(output_error)?;
        let mut value = String::new();
        if io::stdin().read_line(&mut value).map_err(output_error)? == 0 {
            return Ok(None);
        }
        let value = value.trim();
        if value.is_empty() && index != 0 {
            return Ok(None);
        }
        args.push(if value.is_empty() { "." } else { value }.to_owned());
    }
    Ok(Some(args))
}

fn select() -> Result<Option<usize>> {
    #[cfg(unix)]
    let _terminal = RawTerminal::enter()?;
    let mut selected = 0;
    loop {
        draw(selected)?;
        let mut key = [0];
        io::stdin().read_exact(&mut key).map_err(output_error)?;
        match key[0] {
            b'\r' | b'\n' => return Ok(Some(selected)),
            b'q' | 3 => return Ok(None),
            b'1'..=b'7' => return Ok(Some((key[0] - b'1') as usize)),
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

#[cfg(not(unix))]
fn escape_byte() -> Result<Option<u8>> {
    Ok(None)
}

fn draw(selected: usize) -> Result<()> {
    let mut out = io::stdout().lock();
    write!(
        out,
        "\x1b[H\x1b[2J\n  Patronus Security\n  ─────────────────────────────────────────\n\n"
    )
    .map_err(output_error)?;
    for (index, (label, _)) in ACTIONS.iter().enumerate() {
        let marker = if index == selected { "❯" } else { " " };
        writeln!(out, "  {marker} {}. {label}", index + 1).map_err(output_error)?;
    }
    let controls = if cfg!(unix) {
        "↑↓ select · Enter run · 1–7 quick select · Esc/q quit"
    } else {
        "Enter run · Type 1–7 then Enter · q quit"
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
