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
        let _ = self.tx.try_send(0);
    }

    pub async fn wait(&self) {
        let _ = self.rx.lock().await.recv().await;
    }
}
