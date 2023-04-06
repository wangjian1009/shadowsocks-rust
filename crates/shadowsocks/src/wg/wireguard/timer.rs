use futures::Future;
use spin::Mutex;
use tokio::time::Duration;

pub trait TimerCaller: Send + Sync {
    fn call(&self, duration: Duration) -> tokio::task::JoinHandle<()>;
}

struct TimerInner<F> {
    callback: F,
}

impl<F, R> TimerCaller for TimerInner<F>
where
    F: (Fn() -> R) + Send + Sync + 'static,
    R: Future<Output = ()> + Send + 'static,
{
    fn call(&self, duration: Duration) -> tokio::task::JoinHandle<()> {
        let cb = (self.callback)();
        tokio::task::spawn(async move {
            tokio::time::sleep(duration).await;
            cb.await
        })
    }
}

pub struct Timer {
    task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    callback: Box<dyn TimerCaller + Send>,
}

impl Timer {
    pub fn stop(&self) {
        let mut task = self.task.lock();
        if let Some(task) = &*task {
            task.abort();
        }
        *task = None;
    }

    pub fn start(&self, duration: Duration) -> bool {
        let mut task = self.task.lock();
        if task.is_some() {
            return false;
        }

        *task = Some(self.callback.call(duration));
        true
    }

    pub fn reset(&self, duration: Duration) {
        let mut task = self.task.lock();
        *task = Some(self.callback.call(duration));
    }
}

pub struct Runner {}

impl Runner {
    pub fn new(_tick: Duration, _slots: usize, _b: usize) -> Self {
        Runner {}
    }

    pub fn timer<F, R>(&self, callback: F) -> Timer
    where
        F: (Fn() -> R) + Send + Sync + 'static,
        R: Future<Output = ()> + Send + 'static,
    {
        Timer {
            task: Mutex::new(None),
            callback: Box::new(TimerInner { callback }),
        }
    }
}
