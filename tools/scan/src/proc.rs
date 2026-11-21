//! Capped child-process runner. Every external command (curl, git) is spawned
//! as an argv array — never through a shell — with stdin/stdout/stderr read
//! under hard byte caps so a hostile or runaway child cannot exhaust memory.

use std::io::{Read, Write};
use std::process::{Child, Command, Stdio};

/// Cap on stderr captured from any child process.
pub const MAX_STDERR_BYTES: usize = 64 * 1024;

pub struct CappedOutput {
    pub stdout: Vec<u8>,
    pub stdout_truncated: bool,
    pub stderr: String,
    pub code: Option<i32>,
}

fn read_capped<R: Read>(mut r: R, cap: usize) -> (Vec<u8>, bool) {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        if buf.len() >= cap + 1 {
            return (buf, true);
        }
        let want = std::cmp::min(chunk.len(), cap + 1 - buf.len());
        match r.read(&mut chunk[..want]) {
            Ok(0) => return (buf, false),
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return (buf, false),
        }
    }
}

/// Run a command with capped stdout. `stdin_data`, if given, is written on a
/// helper thread so a full pipe can never deadlock the read side.
pub fn run_capped(
    program: &str,
    args: &[String],
    stdin_data: Option<&[u8]>,
    max_stdout: usize,
) -> std::io::Result<CappedOutput> {
    let mut cmd = Command::new(program);
    cmd.args(args)
        .stdin(if stdin_data.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child: Child = cmd.spawn()?;

    // stderr reader thread (capped)
    let mut stderr_pipe = child.stderr.take().expect("stderr piped");
    let stderr_handle = std::thread::spawn(move || {
        let (bytes, _) = read_capped(&mut stderr_pipe, MAX_STDERR_BYTES);
        String::from_utf8_lossy(&bytes).into_owned()
    });

    // stdin writer thread
    if let Some(data) = stdin_data {
        let mut stdin_pipe = child.stdin.take().expect("stdin piped");
        let data = data.to_vec();
        std::thread::spawn(move || {
            let _ = stdin_pipe.write_all(&data);
            // drop closes the pipe, signalling EOF to the child
        });
    }

    let mut stdout_pipe = child.stdout.take().expect("stdout piped");
    let (stdout, truncated) = read_capped(&mut stdout_pipe, max_stdout);
    if truncated {
        // Child is producing more than we will ever read; stop it.
        let _ = child.kill();
    }
    let code = child.wait().ok().and_then(|s| s.code());
    let stderr = stderr_handle.join().unwrap_or_default();
    Ok(CappedOutput { stdout, stdout_truncated: truncated, stderr, code })
}
