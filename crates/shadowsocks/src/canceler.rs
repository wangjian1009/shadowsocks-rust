use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::Notify;

struct Inner {
    is_canceled: AtomicBool,
    notify: Notify,
}

pub struct Canceler {
    inner: Arc<Inner>,
}

impl Canceler {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Inner {
                is_canceled: AtomicBool::new(false),
                notify: Notify::new(),
            }),
        }
    }

    pub fn is_canceled(&self) -> bool {
        self.inner.is_canceled.load(Ordering::SeqCst)
    }

    pub fn cancel(&self) {
        let is_canceled = self.inner.is_canceled.swap(true, Ordering::SeqCst);
        if is_canceled {
        } else {
            self.inner.notify.notify_waiters();
        }
    }

    pub fn waiter(&self) -> CancelWaiter {
        CancelWaiter {
            inner: Some(self.inner.clone()),
        }
    }
}

#[derive(Clone)]
pub struct CancelWaiter {
    inner: Option<Arc<Inner>>,
}

impl CancelWaiter {
    pub fn none() -> Self {
        Self { inner: None }
    }

    pub fn is_canceled(&self) -> bool {
        match self.inner.as_ref() {
            Some(inner) => inner.is_canceled.load(Ordering::SeqCst),
            None => false,
        }
    }

    pub async fn wait(&self) {
        match self.inner.as_ref() {
            Some(inner) => inner.notify.notified().await,
            None => futures::future::pending().await,
        }
    }
}
