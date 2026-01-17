use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Wrap},
    Frame,
};

use crate::state::AppState;

// Available commands with argument info: (command, description, arg_name, arg_help)
const COMMANDS: &[(&str, &str, Option<(&str, &str)>)] = &[
    ("/add", "Add a contact", Some(("<username>", "The username to add (e.g., brave-falcon)"))),
    ("/help", "Show available commands", None),
    ("/quit", "Exit whspr", None),
    ("/q", "Exit whspr", None),
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
    // Calculate suggestions
    let suggestions = get_suggestions(&state.input);
    let suggestion_count = suggestions.len();
    let input_height = if suggestion_count > 0 { 3 + suggestion_count as u16 } else { 3 };

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
    render_input(frame, state, chunks[1], &suggestions);
}

enum Suggestion {
    Command { cmd: &'static str, desc: &'static str },
    Argument { arg: &'static str, help: &'static str },
}

fn get_suggestions(input: &str) -> Vec<Suggestion> {
    if !input.starts_with('/') {
        return vec![];
    }

    // Check if we're in argument mode (command + space)
    if input.contains(' ') {
        let cmd_part = input.split_whitespace().next().unwrap_or("");
        // Find matching command
        if let Some((_, _, Some((arg, help)))) = COMMANDS.iter()
            .find(|(cmd, _, _)| *cmd == cmd_part)
        {
            return vec![Suggestion::Argument { arg, help }];
        }
        return vec![];
    }

    // Show matching commands (max 4)
    let input_lower = input.to_lowercase();
    COMMANDS.iter()
        .filter(|(cmd, _, _)| cmd.starts_with(&input_lower))
        .take(4)
        .map(|(cmd, desc, _)| Suggestion::Command { cmd, desc })
        .collect()
}

fn render_input(frame: &mut Frame, state: &AppState, area: Rect, suggestions: &[Suggestion]) {
    let suggestion_count = suggestions.len();

    let constraints: Vec<Constraint> = if suggestion_count > 0 {
        let mut c = vec![Constraint::Length(3)]; // Input box
        for _ in 0..suggestion_count {
            c.push(Constraint::Length(1)); // Each suggestion line
        }
        c
    } else {
        vec![Constraint::Length(3)]
    };

    let inner_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(area);

    // Input with block cursor
    let input_line = Line::from(vec![
        Span::raw(&state.input),
        Span::styled("█", Style::default().fg(Color::White).add_modifier(Modifier::SLOW_BLINK)),
    ]);

    let input_widget = Paragraph::new(input_line)
        .block(Block::default().title(" > ").borders(Borders::ALL));
    frame.render_widget(input_widget, inner_chunks[0]);

    // Render suggestions below input
    for (i, suggestion) in suggestions.iter().enumerate() {
        let line = match suggestion {
            Suggestion::Command { cmd, desc } => {
                let ghost = if cmd.starts_with(&state.input) {
                    &cmd[state.input.len()..]
                } else {
                    ""
                };
                Line::from(vec![
                    Span::raw("  "),
                    Span::styled(*cmd, Style::default().fg(Color::Yellow)),
                    Span::styled(ghost, Style::default().fg(Color::DarkGray)),
                    Span::raw("  "),
                    Span::styled(*desc, Style::default().fg(Color::DarkGray)),
                ])
            }
            Suggestion::Argument { arg, help } => {
                Line::from(vec![
                    Span::raw("  "),
                    Span::styled(*arg, Style::default().fg(Color::Magenta)),
                    Span::raw("  "),
                    Span::styled(*help, Style::default().fg(Color::DarkGray).add_modifier(Modifier::ITALIC)),
                ])
            }
        };
        let widget = Paragraph::new(line);
        frame.render_widget(widget, inner_chunks[i + 1]);
    }
}
