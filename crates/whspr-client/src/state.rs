use std::collections::HashMap;
use whspr_protocol::{Identity, PublicKeyBundle, crypto::RatchetSession};

#[derive(Debug, Clone)]
pub struct Message {
    pub from: String,
    pub content: String,
    pub timestamp: u64,
    pub outgoing: bool,
}

#[derive(Debug, Clone)]
pub struct Contact {
    pub username: String,
    pub keys: PublicKeyBundle,
    pub online: bool,
}

pub struct Conversation {
    pub contact: Contact,
    pub messages: Vec<Message>,
    pub ratchet: Option<RatchetSession>,
    pub unread: usize,
}

impl Conversation {
    pub fn new(contact: Contact) -> Self {
        Self {
            contact,
            messages: Vec::new(),
            ratchet: None,
            unread: 0,
        }
    }

    pub fn add_message(&mut self, msg: Message) {
        if !msg.outgoing {
            self.unread += 1;
        }
        self.messages.push(msg);
    }

    pub fn mark_read(&mut self) {
        self.unread = 0;
    }
}

pub struct AppState {
    pub identity: Identity,
    pub username: String,
    pub conversations: HashMap<String, Conversation>,
    pub active_conversation: Option<String>,
    pub input: String,
    pub server_addr: String,
    pub connected: bool,
}

impl AppState {
    pub fn new(identity: Identity, server_addr: String) -> Self {
        let username = identity.username().to_string();
        Self {
            identity,
            username,
            conversations: HashMap::new(),
            active_conversation: None,
            input: String::new(),
            server_addr,
            connected: false,
        }
    }

    pub fn get_or_create_conversation(&mut self, contact: Contact) -> &mut Conversation {
        let username = contact.username.clone();
        self.conversations.entry(username.clone())
            .or_insert_with(|| Conversation::new(contact))
    }

    pub fn active_conversation(&self) -> Option<&Conversation> {
        self.active_conversation.as_ref()
            .and_then(|name| self.conversations.get(name))
    }

    pub fn active_conversation_mut(&mut self) -> Option<&mut Conversation> {
        let name = self.active_conversation.clone()?;
        self.conversations.get_mut(&name)
    }

    pub fn select_conversation(&mut self, username: &str) {
        if self.conversations.contains_key(username) {
            self.active_conversation = Some(username.to_string());
            if let Some(conv) = self.conversations.get_mut(username) {
                conv.mark_read();
            }
        }
    }

    pub fn conversation_list(&self) -> Vec<(&String, &Conversation)> {
        let mut list: Vec<_> = self.conversations.iter().collect();
        // Sort by most recent message
        list.sort_by(|a, b| {
            let a_time = a.1.messages.last().map(|m| m.timestamp).unwrap_or(0);
            let b_time = b.1.messages.last().map(|m| m.timestamp).unwrap_or(0);
            b_time.cmp(&a_time)
        });
        list
    }

    pub fn total_unread(&self) -> usize {
        self.conversations.values().map(|c| c.unread).sum()
    }
}
