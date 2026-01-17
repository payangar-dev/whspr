use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Wrap},
    Frame,
};

use crate::state::AppState;

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
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(3)])
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

    // Input area
    let input = Paragraph::new(state.input.as_str())
        .block(Block::default().title(" > ").borders(Borders::ALL));
    frame.render_widget(input, chunks[1]);
}
