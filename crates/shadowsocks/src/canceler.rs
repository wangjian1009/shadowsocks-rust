use std::{collections::HashMap, sync::Arc};
use tokio::sync::oneshot;

struct CancelerData {
    waiters: spin::Mutex<Option<(u32, HashMap<u32, oneshot::Receiver<()>>)>>,
}

pub struct Canceler {
    data: Arc<CancelerData>,
}

impl Canceler {
    pub fn new() -> Self {
        Self {
            data: Arc::new(CancelerData {
                waiters: spin::Mutex::new(Some((0, HashMap::new()))),
            }),
        }
    }

    pub fn is_canceled(&self) -> bool {
        self.data.waiters.lock().is_none()
    }

    pub fn cancel(&self) {
        let _ = self.data.waiters.lock().take();
    }

    pub fn waiter(&self) -> CancelWaiter {
        let (id, tx) = {
            let mut self_waiters = self.data.waiters.lock();
            if let Some(self_waiters) = &mut *self_waiters {
                self_waiters.0 += 1;
                let new_id = self_waiters.0;
                let (tx, rx) = oneshot::channel();
                self_waiters.1.insert(new_id, rx);
                (new_id, tx)
            } else {
                return CancelWaiter {
                    id: 0,
                    canceler: self.data.clone(),
                    tx: None,
                };
            }
        };

        // tracing::error!("xxxxxx: CancelWaiter {} created", id);
        CancelWaiter {
            id,
            canceler: self.data.clone(),
            tx: Some(tx),
        }
    }
}

impl Default for Canceler {
    fn default() -> Self {
        Self::new()
    }
}

pub struct CancelWaiter {
    id: u32,
    canceler: Arc<CancelerData>,
    tx: Option<oneshot::Sender<()>>,
}

impl Drop for CancelWaiter {
    fn drop(&mut self) {
        self.canceler.waiters.lock().as_mut().map(|s| {
            if let Some(_r) = s.1.remove(&self.id) {
                // tracing::error!("xxxxxx: CancelWaiter {} remove", self.id);
            }
        });
    }
}

impl CancelWaiter {
    pub async fn wait(&mut self) {
        if let Some(tx) = self.tx.as_mut() {
            let _ = tx.closed().await;
        }
    }
}
