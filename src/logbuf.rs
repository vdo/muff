//! In-memory capture of tracing output for the TUI.
//!
//! While the alternate screen is active, any log line written to the
//! terminal (stderr/stdout) corrupts the UI — on every screen, not just
//! one. Instead, all tracing events are appended to this shared ring
//! buffer and rendered only where the UI chooses to show them (the
//! dashboard log pane). Nothing ever reaches the terminal directly.

use std::collections::VecDeque;
use std::io::Write;
use std::sync::{Arc, Mutex};

/// Maximum number of log lines kept in memory (oldest are dropped).
const MAX_LOG_LINES: usize = 500;

/// Shared handle to the captured log lines.
///
/// Clone it freely: every clone points at the same underlying buffer.
/// Implements [`tracing_subscriber::fmt::MakeWriter`] so it can be plugged
/// straight into the fmt subscriber.
#[derive(Clone, Default)]
pub struct LogBuffer {
    lines: Arc<Mutex<VecDeque<String>>>,
}

impl LogBuffer {
    pub fn new() -> Self {
        Self::default()
    }

    /// The most recent `n` lines, oldest first.
    pub fn tail(&self, n: usize) -> Vec<String> {
        let lines = self.lines.lock().unwrap_or_else(|e| e.into_inner());
        lines.iter().rev().take(n).rev().cloned().collect()
    }

    /// Append one complete line (used by the writer; public for tests).
    #[doc(hidden)]
    pub fn push_line(&self, line: String) {
        let mut lines = self.lines.lock().unwrap_or_else(|e| e.into_inner());
        if lines.len() >= MAX_LOG_LINES {
            lines.pop_front();
        }
        lines.push_back(line);
    }
}

/// Per-event writer produced by [`LogBuffer`]; complete (newline-terminated)
/// lines are moved into the shared buffer.
pub struct LogWriter {
    buffer: LogBuffer,
    partial: String,
}

impl Write for LogWriter {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.partial.push_str(&String::from_utf8_lossy(data));
        while let Some(pos) = self.partial.find('\n') {
            let line: String = self.partial.drain(..=pos).collect();
            self.buffer.push_line(line.trim_end().to_string());
        }
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if !self.partial.is_empty() {
            self.buffer.push_line(std::mem::take(&mut self.partial));
        }
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogBuffer {
    type Writer = LogWriter;

    fn make_writer(&'a self) -> Self::Writer {
        LogWriter {
            buffer: self.clone(),
            partial: String::new(),
        }
    }
}
