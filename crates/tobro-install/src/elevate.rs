//! Elevated-process execution and the quoting rules for generated scripts.
//!
//! Every privileged action is one generated script run through the platform
//! elevation mechanism:
//!
//! | OS | Runner | Prompt |
//! |---|---|---|
//! | Linux | `pkexec /bin/sh -c <script>` | polkit authorization dialog |
//! | macOS | `osascript -e 'do shell script "<script>" with administrator privileges'` | administrator password / Touch ID |
//! | Windows | `powershell Start-Process -Verb RunAs` of a generated `.ps1` | UAC consent |
//!
//! [`ProcessRunner`] is the production implementation; tests inject a
//! recording [`Runner`] so nothing here ever elevates in CI.

use std::io;

/// Command execution abstraction (production: real processes; tests: a
/// recorder). `capture` additionally returns stdout/stderr for status
/// parsing and error tails.
pub trait Runner: Send + Sync {
    /// Run a program to completion; returns its exit code (or -1 when it was
    /// killed by a signal).
    ///
    /// # Errors
    ///
    /// When the program could not be spawned (missing binary, permission).
    fn run(&self, program: &str, args: &[String]) -> io::Result<i32>;

    /// Run a program to completion and capture its output.
    ///
    /// # Errors
    ///
    /// When the program could not be spawned.
    fn capture(&self, program: &str, args: &[String]) -> io::Result<Captured>;
}

/// Captured output of one completed command.
#[derive(Debug, Clone)]
pub struct Captured {
    /// Exit code (or -1 when killed by a signal).
    pub code: i32,
    /// Standard output, lossily decoded.
    pub stdout: String,
    /// Standard error, lossily decoded.
    pub stderr: String,
}

impl Captured {
    /// `true` when the command exited zero.
    pub fn ok(&self) -> bool {
        self.code == 0
    }

    /// A bounded stderr tail for error messages (errors can be long and the
    /// interesting part is usually the end).
    #[must_use]
    pub fn stderr_tail(&self, max: usize) -> String {
        let clean: String = self.stderr.chars().filter(|c| !c.is_control()).collect();
        let count = clean.chars().count();
        if count <= max {
            clean
        } else {
            clean.chars().skip(count - max).collect()
        }
    }
}

/// Production runner: real child processes.
#[derive(Debug, Default, Clone, Copy)]
pub struct ProcessRunner;

impl Runner for ProcessRunner {
    fn run(&self, program: &str, args: &[String]) -> io::Result<i32> {
        std::process::Command::new(program)
            .args(args)
            .status()
            .map(|status| status.code().unwrap_or(-1))
    }

    fn capture(&self, program: &str, args: &[String]) -> io::Result<Captured> {
        let output = std::process::Command::new(program).args(args).output()?;
        Ok(Captured {
            code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

// --- Embedding rules -------------------------------------------------------

/// Reject strings that cannot be safely embedded in any of the generated
/// scripts: line breaks and NUL could break out of the quoting below.
///
/// Everything else is handled by the per-shell quoting helpers.
///
/// # Errors
///
/// [`InstallError::SourceInvalid`] naming `what` on any rejection.
pub fn validate_embeddable(text: &str, what: &'static str) -> Result<(), crate::InstallError> {
    if text.contains(['\0', '\n', '\r']) {
        return Err(crate::InstallError::SourceInvalid(format!(
            "{what} contains control characters and cannot be embedded in the installer script"
        )));
    }
    Ok(())
}

/// POSIX-sh single-quote a string (`'` becomes the `'\''` dance). The result
/// is safe inside a `sh -c` script for any validated input.
#[must_use]
pub fn sh_single_quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', r"'\''"))
}

/// PowerShell single-quote a string (`'` doubles). Safe for any validated
/// input embedded in a `.ps1` or `-Command` argument.
#[must_use]
pub fn powershell_quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', "''"))
}

/// Escape a string for embedding inside an AppleScript double-quoted string
/// (backslashes and quotes). Used for the `do shell script "..."` body.
#[must_use]
pub fn apple_script_escape(text: &str) -> String {
    text.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn sh_quoting_survives_metacharacters() {
        assert_eq!(
            sh_single_quote("/usr/local/bin/helper"),
            "'/usr/local/bin/helper'"
        );
        assert_eq!(sh_single_quote("it's"), r"'it'\''s'");
        // Quoting turns shell metacharacters into plain data.
        assert_eq!(sh_single_quote("$(id)"), "'$(id)'");
        assert_eq!(sh_single_quote("a b\tc"), "'a b\tc'");
    }

    #[test]
    fn powershell_quoting_doubles_quotes() {
        assert_eq!(
            powershell_quote("C:\\Program Files\\Tobro"),
            "'C:\\Program Files\\Tobro'"
        );
        assert_eq!(powershell_quote("it''s"), "'it''''s'");
    }

    #[test]
    fn apple_script_escaping_handles_quotes_and_backslashes() {
        assert_eq!(apple_script_escape("plain"), "plain");
        assert_eq!(apple_script_escape(r"a\b"), r"a\\b");
        assert_eq!(apple_script_escape("a\"b"), "a\\\"b");
    }

    #[test]
    fn embeddable_validation_rejects_line_breaks_and_nul() {
        validate_embeddable("/usr/local/bin/tobro-helper", "path").unwrap();
        assert!(validate_embeddable("a\nb", "path").is_err());
        assert!(validate_embeddable("a\rb", "path").is_err());
        assert!(validate_embeddable("a\0b", "path").is_err());
    }

    #[test]
    fn stderr_tail_is_bounded_and_control_free() {
        let captured = Captured {
            code: 1,
            stdout: String::new(),
            stderr: format!("{}\tignored\n", "x".repeat(30)) + "the real error",
        };
        let tail = captured.stderr_tail(10);
        assert_eq!(tail, "real error", "control characters are stripped");
        assert!(tail.chars().count() <= 10);
    }
}
