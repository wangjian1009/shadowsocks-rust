use std::{fmt, string::String, sync::Arc};
use tokio::{
    io,
    sync::mpsc::{channel, Receiver, Sender},
};

struct StartStatChild {
    sender: Arc<Sender<String>>,
    receiver: Receiver<String>,
    count: u16,
}

impl StartStatChild {
    pub fn new() -> Self {
        let (r, w) = channel(1);
        Self {
            sender: Arc::new(r),
            receiver: w,
            count: 0,
        }
    }
}

pub struct StartStat {
    name: Option<String>,
    parent_sender: Option<Arc<Sender<String>>>,
    child: spin::Mutex<Option<StartStatChild>>,
}

impl StartStat {
    pub fn create() -> Self {
        Self {
            name: None,
            parent_sender: None,
            child: spin::Mutex::new(None),
        }
    }

    pub async fn wait(self) -> io::Result<()> {
        let child = self.child.lock().take();

        if let Some(StartStatChild {
            sender: _,
            mut receiver,
            count,
        }) = child
        {
            // let mut vfut = Vec::new();

            let mut received_count = 0;
            while received_count < count {
                match receiver.recv().await {
                    Some(name) => {
                        received_count = received_count + 1;
                        tracing::info!("{self}: [{received_count}/{}]: {} started", count, name);
                    }
                    None => {
                        return Err(io::Error::new(io::ErrorKind::Other, "wait child channel closed"));
                    }
                }
            }
        }

        if let Some(parent_sender) = &self.parent_sender {
            match parent_sender.send(self.name.clone().unwrap()).await {
                Ok(()) => {}
                Err(_err) => {
                    tracing::error!(err = ?_err, "{self}: send notify error");
                    return Err(io::Error::new(io::ErrorKind::Other, "send notify error"));
                }
            }
        }

        Ok(())
    }

    pub async fn notify(&self) -> io::Result<()> {
        if self.child.lock().is_some() {
            panic!("{self}: can`t notify with child");
        }

        match &self.parent_sender {
            Some(parent_sender) => match parent_sender.send(self.name.clone().unwrap()).await {
                Ok(()) => {}
                Err(_err) => {
                    tracing::error!(err = ?_err, "{self}: send notify error");
                    return Err(io::Error::new(io::ErrorKind::Other, "send notify error"));
                }
            },
            None => {
                panic!("{self}: no parent sender");
            }
        }

        Ok(())
    }

    pub fn new_child(&mut self, child_name: &str) -> StartStat {
        let name = match &self.name {
            Some(name) => format!("{}.{}", name, child_name),
            None => child_name.to_owned(),
        };

        let sender = {
            let mut child = self.child.lock();
            if child.is_none() {
                *child = Some(StartStatChild::new());
            }

            let child = child.as_mut().unwrap();
            child.count = child.count + 1;
            child.sender.clone()
        };

        Self {
            name: Some(name),
            parent_sender: Some(sender),
            child: spin::Mutex::new(None),
        }
    }
}

impl fmt::Display for StartStat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(name) = self.name.as_ref() {
            write!(f, "StartStat[{name}]")
        } else {
            write!(f, "StartStat")
        }
    }
}
