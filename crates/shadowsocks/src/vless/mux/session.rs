use std::{collections::HashMap, fmt, sync::Arc};
use tokio::{
    sync::{mpsc, Mutex},
    task::JoinHandle,
};

use super::{frame::Destination, SharedStream};

pub enum SessionWay {
    Outgoing,
    Incoming,
}

pub struct SessionMetadata {
    pub way: SessionWay,
    pub target_addr: Destination,
    pub id: u16,
}

impl fmt::Display for SessionMetadata {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.way {
            &SessionWay::Incoming => {
                write!(f, "S #{} [{}]", self.id, self.target_addr)
            }
            &SessionWay::Outgoing => {
                write!(f, "C #{} [{}]", self.id, self.target_addr)
            }
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum SessionReadCmd {
    Read(usize),
    Close,
}

pub struct SessionContext {
    base_stream: SharedStream,
    read_done_sender: mpsc::Sender<()>,
    write_lock: Arc<Mutex<()>>,
}

impl SessionContext {
    pub fn new(base_stream: SharedStream) -> (Self, mpsc::Receiver<()>) {
        let (read_done_sender, read_done_r) = mpsc::channel::<()>(1);
        (
            Self {
                base_stream,
                read_done_sender,
                write_lock: Arc::new(Mutex::new(())),
            },
            read_done_r,
        )
    }

    #[inline]
    pub fn base_stream(&self) -> SharedStream {
        self.base_stream.clone()
    }

    #[inline]
    pub fn write_lock(&self) -> Arc<Mutex<()>> {
        self.write_lock.clone()
    }
}

pub struct Session {
    meta: Arc<SessionMetadata>,
    context: Arc<SessionContext>,
    read_cmd_sender: mpsc::Sender<SessionReadCmd>,
    serve_task: Option<JoinHandle<()>>,
}

impl Session {
    pub fn new(
        meta: SessionMetadata,
        context: Arc<SessionContext>,
        read_cmd_sender: mpsc::Sender<SessionReadCmd>,
    ) -> Self {
        let meta = Arc::new(meta);

        Self {
            meta,
            context,
            read_cmd_sender,
            serve_task: None,
        }
    }

    #[inline]
    pub fn meta(&self) -> &SessionMetadata {
        self.meta.as_ref()
    }

    #[inline]
    pub fn context(&self) -> &SessionContext {
        self.context.as_ref()
    }

    #[inline]
    pub fn read_done_sender(&self) -> &mpsc::Sender<()> {
        &self.context.read_done_sender
    }

    #[inline]
    pub fn read_cmd_sender(&self) -> &mpsc::Sender<SessionReadCmd> {
        &self.read_cmd_sender
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if let Some(serve_task) = self.serve_task.as_mut() {
            serve_task.abort();
        }
        log::info!("#{}: connection droped", self.meta());
    }
}

pub struct SessionManager {
    sessions: HashMap<u16, Arc<Session>>,
}

impl SessionManager {
    #[inline]
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
        }
    }

    #[inline]
    pub fn count(&self) -> usize {
        self.sessions.len()
    }

    #[inline]
    pub fn add(&mut self, session: Arc<Session>) {
        let id = session.meta.id;
        self.sessions.insert(id, session);
    }

    #[inline]
    pub fn remove(&mut self, session_id: u16) -> Option<Arc<Session>> {
        self.sessions.remove(&session_id)
    }

    #[inline]
    pub fn get(&self, session_id: u16) -> Option<Arc<Session>> {
        self.sessions.get(&session_id).map(|e| e.clone())
    }
}
