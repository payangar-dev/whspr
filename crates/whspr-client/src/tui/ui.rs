use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Wrap},
    Frame,
};

use crate::state::AppState;

// Available commands for suggestions
const COMMANDS: &[(&str, &str)] = &[
    ("/add", "Add a contact"),
    ("/help", "Show help"),
    ("/quit", "Exit"),
    ("/q", "Exit"),
];

pub fn render(frame: &mut Frame, state: &AppState) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(25), Constraint::Min(0)])
        .split(frame.area());

    render_sidebar(frame, state, chunks[0]);
    render_main(frame, state, chunks[1]);
}

fn render_sidebar(frame: &mut Frame, state: &AppState, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0)])
        .split(area);

    // User info
    let status = if state.connected { "online" } else { "offline" };
    let user_block = Block::default()
        .title(format!(" {} ", state.username))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan));

    let user_text = Paragraph::new(status)
        .style(Style::default().fg(if state.connected { Color::Green } else { Color::Red }))
        .block(user_block);
    frame.render_widget(user_text, chunks[0]);

    // Conversation list
    let conversations: Vec<ListItem> = state
        .conversation_list()
        .iter()
        .map(|(name, conv)| {
            let style = if Some(name.as_str()) == state.active_conversation.as_deref() {
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };

            let prefix = if conv.contact.online { "+" } else { "-" };
            let unread = if conv.unread > 0 {
                format!(" ({})", conv.unread)
            } else {
                String::new()
            };

            ListItem::new(format!("{} {}{}", prefix, name, unread)).style(style)
        })
        .collect();

    let list = List::new(conversations)
        .block(Block::default().title(" Chats ").borders(Borders::ALL));
    frame.render_widget(list, chunks[1]);
}

fn render_main(frame: &mut Frame, state: &AppState, area: Rect) {
    // Calculate if we need space for suggestions
    let suggestion = get_command_suggestion(&state.input);
    let input_height = if suggestion.is_some() { 4 } else { 3 };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(input_height)])
        .split(area);

    // Messages area
    if let Some(conv) = state.active_conversation() {
        let messages: Vec<Line> = conv
            .messages
            .iter()
            .map(|msg| {
                let style = if msg.outgoing {
                    Style::default().fg(Color::Cyan)
                } else {
                    Style::default().fg(Color::Green)
                };
                let prefix = if msg.outgoing { ">" } else { "<" };
                Line::from(vec![
                    Span::styled(format!("{} ", prefix), style),
                    Span::raw(&msg.content),
                ])
            })
            .collect();

        let messages_widget = Paragraph::new(messages)
            .block(
                Block::default()
                    .title(format!(" {} ", conv.contact.username))
                    .borders(Borders::ALL),
            )
            .wrap(Wrap { trim: false });
        frame.render_widget(messages_widget, chunks[0]);
    } else {
        let placeholder = Paragraph::new("Select a conversation or /add <username>")
            .style(Style::default().fg(Color::DarkGray))
            .block(Block::default().title(" Messages ").borders(Borders::ALL));
        frame.render_widget(placeholder, chunks[0]);
    }

    // Input area with cursor and suggestions
    render_input(frame, state, chunks[1], suggestion);
}

fn get_command_suggestion(input: &str) -> Option<(&'static str, &'static str)> {
    if !input.starts_with('/') || input.len() < 2 {
        return None;
    }

    let input_lower = input.to_lowercase();

    // Find first matching command
    COMMANDS.iter()
        .find(|(cmd, _)| cmd.starts_with(&input_lower) && *cmd != input_lower)
        .copied()
}

fn render_input(frame: &mut Frame, state: &AppState, area: Rect, suggestion: Option<(&str, &str)>) {
    let inner_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(if suggestion.is_some() {
            vec![Constraint::Length(1), Constraint::Length(3)]
        } else {
            vec![Constraint::Length(3)]
        })
        .split(area);

    let (input_area, suggestion_area) = if suggestion.is_some() {
        (inner_chunks[1], Some(inner_chunks[0]))
    } else {
        (inner_chunks[0], None)
    };

    // Show suggestion line above input
    if let (Some(area), Some((cmd, desc))) = (suggestion_area, suggestion) {
        let ghost = &cmd[state.input.len()..];
        let suggestion_line = Line::from(vec![
            Span::raw("  "),
            Span::styled(&state.input, Style::default().fg(Color::White)),
            Span::styled(ghost, Style::default().fg(Color::DarkGray)),
            Span::styled(format!("  {}", desc), Style::default().fg(Color::DarkGray).add_modifier(Modifier::ITALIC)),
        ]);
        let suggestion_widget = Paragraph::new(suggestion_line);
        frame.render_widget(suggestion_widget, area);
    }

    // Input with cursor
    let input_line = Line::from(vec![
        Span::raw(&state.input),
        Span::styled("│", Style::default().fg(Color::Cyan).add_modifier(Modifier::SLOW_BLINK)),
    ]);

    let input_widget = Paragraph::new(input_line)
        .block(Block::default().title(" > ").borders(Borders::ALL));
    frame.render_widget(input_widget, input_area);
}
