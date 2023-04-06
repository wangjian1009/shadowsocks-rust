use spin::Mutex;
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::Notify;

struct Inner<T> {
    messages: Mutex<(VecDeque<T>, bool)>,
    notify_on_sent: Notify,
}

#[derive(Clone)]
pub struct Receiver<T> {
    inner: Arc<Inner<T>>,
}

impl<T> Receiver<T> {
    pub async fn recv(&self) -> Option<T> {
        loop {
            // 获取许可证并尝试从队列中取出数据
            {
                let mut locked_queue = self.inner.messages.lock();
                if locked_queue.1 {
                    return None;
                } else if let Some(d) = locked_queue.0.pop_front() {
                    return Some(d);
                }
            }

            self.inner.notify_on_sent.notified().await
        }
    }
}

pub struct ParallelQueue<T> {
    _capacity: usize,
    inner: Arc<Inner<T>>,
}

impl<T> ParallelQueue<T> {
    /// Create a new ParallelQueue instance
    ///
    /// # Arguments
    ///
    /// - `queues`: number of readers
    /// - `capacity`: capacity of each internal queue
    pub fn new(queues: usize, capacity: usize) -> (Self, Vec<Receiver<T>>) {
        let inner = Arc::new(Inner {
            messages: Mutex::new((VecDeque::new(), false)),
            notify_on_sent: Notify::new(),
        });

        let mut receivers = Vec::with_capacity(queues);
        for _ in 0..queues {
            receivers.push(Receiver { inner: inner.clone() });
        }
        (
            ParallelQueue {
                _capacity: capacity,
                inner,
            },
            receivers,
        )
    }

    pub async fn send(&self, v: T) {
        {
            let mut locked_queue = self.inner.messages.lock();
            if locked_queue.1 {
                return;
            }

            locked_queue.0.push_back(v);
        }

        // Send a notification to one of the calls currently
        // waiting in a call to `recv`.
        self.inner.notify_on_sent.notify_one();
    }

    pub fn close(&self) {
        {
            let mut locked_queue = self.inner.messages.lock();
            locked_queue.1 = true;
            locked_queue.0.clear();
        }

        self.inner.notify_on_sent.notify_waiters()
    }
}
