//! In-memory daemon log ring buffer (`daemon.logs`).
//!
//! A `tracing_subscriber` writer tees every formatted log line into a bounded
//! ring buffer so IPC clients (`tobroctl logs`, the GUI logs window) can fetch
//! recent output without reading files. Lines are redacted at capture time
//! (bridge material, proxy credentials, client-auth keys) so the buffer is
//! safe to expose over IPC; see [`crate::redact`].

use std::collections::VecDeque;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use crate::redact::redact_secrets;

/// Default number of retained log lines.
pub const DEFAULT_CAPACITY: usize = 1000;
/// Default number of lines returned by `daemon.logs` when unspecified.
pub const DEFAULT_REQUESTED_LINES: usize = 200;
/// Longest single retained line; longer lines are truncated.
const MAX_LINE_LEN: usize = 4000;

/// Bounded ring buffer of recent, redacted daemon log lines.
#[derive(Debug)]
pub struct LogBuffer {
    inner: Mutex<VecDeque<String>>,
    capacity: usize,
    total_lines: AtomicU64,
}

/// Shared handle used by the tracing writer and the IPC control plane.
pub type LogBufferShared = Arc<LogBuffer>;

impl LogBuffer {
    /// Create a ring buffer holding the most recent `capacity` lines.
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        Self {
            inner: Mutex::new(VecDeque::with_capacity(capacity)),
            capacity,
            total_lines: AtomicU64::new(0),
        }
    }

    /// Shared wrapper for [`LogBuffer::new`].
    pub fn shared(capacity: usize) -> LogBufferShared {
        Arc::new(Self::new(capacity))
    }

    /// Store one line. Secrets are redacted before the line enters the buffer.
    pub fn push(&self, line: &str) {
        let line = line.trim_end_matches(['\r', '\n']);
        if line.is_empty() {
            return;
        }
        let line = redact_secrets(&truncate_line(line));
        self.total_lines.fetch_add(1, Ordering::Relaxed);
        let mut guard = match self.inner.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if guard.len() >= self.capacity {
            guard.pop_front();
        }
        guard.push_back(line);
    }

    /// The most recent `n` lines, plus whether the buffer has more than `n`.
    pub fn last(&self, n: usize) -> (Vec<String>, bool) {
        let n = n.max(1);
        let guard = match self.inner.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let total = guard.len();
        let start = total.saturating_sub(n);
        (guard.iter().skip(start).cloned().collect(), total > n)
    }

    /// Capacity of the ring buffer.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Total lines captured since daemon start (including evicted ones).
    pub fn total_lines(&self) -> u64 {
        self.total_lines.load(Ordering::Relaxed)
    }
}

fn truncate_line(line: &str) -> String {
    if line.len() <= MAX_LINE_LEN {
        return line.to_owned();
    }
    // Cut on a char boundary so multi-byte characters stay intact.
    let mut end = MAX_LINE_LEN;
    while end > 0 && !line.is_char_boundary(end) {
        end -= 1;
    }
    let mut out = String::from(&line[..end]);
    out.push_str(" …[truncated]");
    out
}

/// `tracing_subscriber` writer factory that tees log output to stderr, an
/// optional file, and the shared ring buffer.
#[derive(Debug)]
pub struct LogCapture {
    ring: LogBufferShared,
    file: Option<Arc<Mutex<std::fs::File>>>,
}

impl LogCapture {
    /// Capture into `ring`, teeing to `file` when given.
    pub fn new(ring: LogBufferShared, file: Option<Arc<Mutex<std::fs::File>>>) -> Self {
        Self { ring, file }
    }
}

/// Per-event writer handed to the `tracing` formatter.
pub struct LogWriter<'a> {
    ring: &'a LogBufferShared,
    file: Option<&'a Arc<Mutex<std::fs::File>>>,
    buffered: String,
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogCapture {
    type Writer = LogWriter<'a>;

    fn make_writer(&'a self) -> Self::Writer {
        LogWriter {
            ring: &self.ring,
            file: self.file.as_ref(),
            buffered: String::new(),
        }
    }
}

impl std::io::Write for LogWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // The formatter writes the whole line (plus newline) per event; split
        // on newlines so each line lands in the buffer exactly once.
        let text = String::from_utf8_lossy(buf);
        self.buffered.push_str(&text);
        while let Some(position) = self.buffered.find('\n') {
            let line: String = self.buffered.drain(..=position).collect();
            self.emit_line(line.trim_end_matches(['\r', '\n']));
        }
        // Always report the full buffer consumed; stderr/file failures are
        // ignored so a broken log sink never breaks the daemon.
        std::io::stderr().write_all(buf)?;
        if let Some(file) = self.file {
            let mut guard = match file.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            let _ = guard.write_all(buf);
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if !self.buffered.is_empty() {
            let rest = std::mem::take(&mut self.buffered);
            self.emit_line(rest.trim_end_matches(['\r', '\n']));
        }
        let _ = std::io::stderr().flush();
        if let Some(file) = self.file {
            let mut guard = match file.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            let _ = guard.flush();
        }
        Ok(())
    }
}

impl Drop for LogWriter<'_> {
    fn drop(&mut self) {
        if !self.buffered.is_empty() {
            let rest = std::mem::take(&mut self.buffered);
            self.emit_line(rest.trim_end_matches(['\r', '\n']));
        }
    }
}

impl LogWriter<'_> {
    fn emit_line(&mut self, line: &str) {
        if !line.is_empty() {
            self.ring.push(line);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use tracing_subscriber::fmt::MakeWriter as _;

    #[test]
    fn ring_buffer_evicts_oldest_and_counts_total() {
        let ring = LogBuffer::new(3);
        for i in 0..5 {
            ring.push(&format!("line-{i}"));
        }
        let (lines, truncated) = ring.last(10);
        assert_eq!(lines, ["line-2", "line-3", "line-4"]);
        assert!(!truncated, "n larger than the buffer is not truncated");
        assert_eq!(ring.total_lines(), 5);

        let (lines, truncated) = ring.last(2);
        assert_eq!(lines, ["line-3", "line-4"]);
        assert!(truncated);
    }

    #[test]
    fn push_redacts_secrets_and_skips_empty_lines() {
        let ring = LogBuffer::new(10);
        ring.push("");
        ring.push("\r\n");
        ring.push("password=hunter2 login ok");
        let (lines, _) = ring.last(10);
        assert_eq!(lines.len(), 1);
        assert!(!lines[0].contains("hunter2"), "secret must be redacted");
    }

    #[test]
    fn long_lines_are_truncated_on_char_boundaries() {
        let ring = LogBuffer::new(2);
        let long = "x".repeat(MAX_LINE_LEN + 50);
        ring.push(&long);
        let (lines, _) = ring.last(1);
        assert!(lines[0].ends_with("…[truncated]"));
        assert!(lines[0].len() < long.len());
        // Multi-byte characters stay intact.
        ring.push(&"é".repeat(MAX_LINE_LEN));
        let (lines, _) = ring.last(1);
        assert!(lines[0].is_char_boundary(0));
        assert!(lines[0].ends_with("…[truncated]") || lines[0].ends_with('é'));
    }

    #[test]
    fn capture_writer_splits_multiline_writes() {
        let ring = LogBuffer::shared(10);
        let capture = LogCapture::new(Arc::clone(&ring), None);
        let mut writer = capture.make_writer();
        writer
            .write_all(b"first line\nsecond\npartial")
            .expect("write");
        drop(writer); // emits the trailing partial line

        let (lines, _) = ring.last(10);
        assert_eq!(lines, ["first line", "second", "partial"]);
    }

    #[test]
    fn capture_writer_tees_to_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("tobrod.log");
        let file = std::fs::File::create(&path).expect("create log file");
        let ring = LogBuffer::shared(10);
        let capture = LogCapture::new(Arc::clone(&ring), Some(Arc::new(Mutex::new(file))));
        let mut writer = capture.make_writer();
        writer.write_all(b"logged line\n").expect("write");
        writer.flush().expect("flush");

        let content = std::fs::read_to_string(&path).expect("read log file");
        assert!(content.contains("logged line"));
        let (lines, _) = ring.last(10);
        assert_eq!(lines, ["logged line"]);
    }
}
