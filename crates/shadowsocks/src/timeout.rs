use futures::Future;
use pin_project::pin_project;
use std::{fmt, pin::Pin, sync::Arc, task::Poll};
use tokio::time::{sleep_until, Duration, Instant, Sleep};

struct Inner {
    duration: Duration,
    deadline: spin::Mutex<Instant>,
}

impl Inner {
    #[inline]
    fn deadline(&self) -> Instant {
        self.deadline.lock().clone()
    }

    #[inline]
    pub fn tick(&self) {
        *self.deadline.lock() = Instant::now() + self.duration;
    }
}

#[pin_project(project = TimeoutWaiterProj)]
pub struct TimeoutWaiter {
    inner: Arc<Inner>,
    #[pin]
    sleep: Sleep,
}

impl TimeoutWaiter {
    pub fn new(duration: Duration) -> TimeoutWaiter {
        let deadline = Instant::now() + duration;
        let sleep = sleep_until(deadline);
        let inner = Arc::new(Inner {
            duration,
            deadline: spin::Mutex::new(deadline),
        });
        TimeoutWaiter { inner, sleep }
    }

    #[inline]
    pub fn tick(&self) {
        self.inner.tick()
    }

    #[inline]
    pub fn ticker(&self) -> TimeoutTicker {
        TimeoutTicker {
            inner: self.inner.clone(),
        }
    }
}

impl Future for TimeoutWaiter {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<()> {
        let TimeoutWaiterProj { mut sleep, inner } = self.project();
        let deadline = *inner.deadline.lock();
        if sleep.deadline() != deadline {
            sleep.as_mut().reset(deadline);
        }
        sleep.poll(cx)
    }
}

impl fmt::Debug for TimeoutWaiter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TimeoutWaiter")
            .field("duration", &self.inner.duration)
            .field("deadline", &self.inner.deadline())
            .finish()
    }
}

#[derive(Clone)]
pub struct TimeoutTicker {
    inner: Arc<Inner>,
}

impl TimeoutTicker {
    #[inline]
    pub fn tick(&self) {
        self.inner.tick()
    }
}

impl fmt::Debug for TimeoutTicker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TimeoutTicker")
            .field("duration", &self.inner.duration)
            .field("deadline", &self.inner.deadline())
            .finish()
    }
}
