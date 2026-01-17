pub mod ui;

use crossterm::{
    event::{self, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::io::{self, Stdout};
use tokio::sync::mpsc;

use crate::state::AppState;

pub enum AppEvent {
    Key(KeyCode, KeyModifiers),
    Tick,
    Quit,
}

pub struct Tui {
    terminal: Terminal<CrosstermBackend<Stdout>>,
}

impl Tui {
    pub fn new() -> io::Result<Self> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen)?;
        let backend = CrosstermBackend::new(stdout);
        let terminal = Terminal::new(backend)?;
        Ok(Self { terminal })
    }

    pub fn draw(&mut self, state: &AppState) -> io::Result<()> {
        self.terminal.draw(|frame| {
            ui::render(frame, state);
        })?;
        Ok(())
    }

    pub fn restore(&mut self) -> io::Result<()> {
        disable_raw_mode()?;
        execute!(self.terminal.backend_mut(), LeaveAlternateScreen)?;
        Ok(())
    }
}

impl Drop for Tui {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

pub async fn run_event_loop(tx: mpsc::Sender<AppEvent>) {
    let tick_rate = std::time::Duration::from_millis(100);

    loop {
        if event::poll(tick_rate).unwrap_or(false) {
            if let Ok(Event::Key(key)) = event::read() {
                if tx.send(AppEvent::Key(key.code, key.modifiers)).await.is_err() {
                    break;
                }
            }
        } else {
            if tx.send(AppEvent::Tick).await.is_err() {
                break;
            }
        }
    }
}
