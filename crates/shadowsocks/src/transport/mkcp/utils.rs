use tokio::sync::{mpsc, Mutex};

#[derive(Debug)]
pub struct Notifier {
    tx: mpsc::Sender<u8>,
    rx: Mutex<mpsc::Receiver<u8>>,
}

impl Notifier {
    pub fn new() -> Self {
        let (tx, rx) = mpsc::channel(1);
        let rx = Mutex::new(rx);
        Self { tx, rx }
    }

    pub fn signal(&self) {
        match self.tx.try_send(0) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Closed(_message)) => {
                // log::info!("xxxxx: signal closed {}", _message)
            }
            Err(mpsc::error::TrySendError::Full(_message)) => {
                // log::info!("xxxxx: signal full {}", _message)
            }
        }
    }

    pub async fn wait(&self) {
        let _ = self.rx.lock().await.recv().await;
    }
}
