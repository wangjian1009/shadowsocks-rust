use futures::Future;
use std::{fmt, pin::Pin};
use tokio::time::{self, Duration, Instant};

pub struct Sleep {
    duration: Duration,
    inner: Pin<Box<time::Sleep>>,
}

impl Sleep {
    pub fn new(duration: Duration) -> Sleep {
        Sleep {
            duration,
            inner: Box::pin(time::sleep(duration)),
        }
    }

    pub async fn reschedule(self: &mut Self) {
        self.inner.as_mut().reset(Instant::now() + self.duration)
    }
}

impl Future for Sleep {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<()> {
        self.inner.as_mut().poll(cx)
    }
}

impl fmt::Debug for Sleep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.inner.as_ref().fmt(f)
    }
}
