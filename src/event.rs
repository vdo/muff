use crossterm::event::{self, Event as CrosstermEvent, KeyEvent, KeyEventKind, MouseEvent};
use std::time::Duration;
use tokio::sync::mpsc;

/// Application events that drive state changes.
#[derive(Debug)]
pub enum AppEvent {
    /// Terminal key press event.
    Key(KeyEvent),
    /// Terminal mouse event (click, scroll, …).
    Mouse(MouseEvent),
    /// Bracketed-paste payload (pasted text arrives as one event).
    Paste(String),
    /// Periodic tick for UI refresh and background updates.
    Tick,
    /// Node status update from background task.
    NodeStatus(crate::rpc::NodeStatus),
    /// Scanner event.
    Scan(crate::wallet::ScanEvent),
    /// Send engine event.
    Send(crate::wallet::SendEvent),
    /// The daemon connection is (re-)established; start the scanner.
    StartScanner,
    /// Shutdown signal.
    Quit,
}

/// Event handler that reads terminal events and produces AppEvents.
pub struct EventHandler {
    tick_rate: Duration,
    tx: mpsc::UnboundedSender<AppEvent>,
}

impl EventHandler {
    pub fn new(tick_rate_ms: u64) -> (Self, mpsc::UnboundedReceiver<AppEvent>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (
            Self {
                tick_rate: Duration::from_millis(tick_rate_ms),
                tx,
            },
            rx,
        )
    }

    /// Start the event loop in a background tokio task.
    pub fn start(&self) {
        let tick_rate = self.tick_rate;
        let tx = self.tx.clone();

        tokio::spawn(async move {
            loop {
                // Poll for events with tick timeout
                if event::poll(tick_rate).unwrap_or(false) {
                    match event::read() {
                        Ok(CrosstermEvent::Key(key)) if key.kind == KeyEventKind::Press => {
                            if tx.send(AppEvent::Key(key)).is_err() {
                                break;
                            }
                        }
                        Ok(CrosstermEvent::Mouse(mouse)) => {
                            if tx.send(AppEvent::Mouse(mouse)).is_err() {
                                break;
                            }
                        }
                        Ok(CrosstermEvent::Paste(text)) => {
                            if tx.send(AppEvent::Paste(text)).is_err() {
                                break;
                            }
                        }
                        Ok(_) => {} // Ignore other events (resize, key release, etc.)
                        Err(_) => break,
                    }
                } else {
                    // Tick
                    if tx.send(AppEvent::Tick).is_err() {
                        break;
                    }
                }
            }
        });
    }

    /// Send a custom event (e.g., from background tasks).
    pub fn sender(&self) -> mpsc::UnboundedSender<AppEvent> {
        self.tx.clone()
    }
}
