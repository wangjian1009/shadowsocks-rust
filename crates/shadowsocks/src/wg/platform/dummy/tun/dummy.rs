// This provides a mock tunnel interface.
// Which enables unit tests where WireGuard interfaces
// are configured to match each other and a full test of:
//
// - Handshake
// - Transport encryption/decryption
//
// Can be executed.

use super::*;

use async_trait::async_trait;
use std::cmp::min;
use std::error::Error;
use std::fmt;
use std::time::Duration;

use tokio::{
    sync::mpsc::{channel, Receiver, Sender},
    sync::Mutex,
};

use hex;
use rand::rngs::OsRng;
use rand::Rng;
use tracing::debug;

pub struct TunTest {}

// Represents the "other end" (kernel/OS end) of the TUN connection:
//
// Used to send/receive packets to the mock WireGuard interface.
pub struct TunFakeIO {
    id: u32,
    store: bool,
    tx: Sender<Vec<u8>>,
    rx: Mutex<Receiver<Vec<u8>>>,
}

pub struct TunReader {
    id: u32,
    rx: Mutex<Receiver<Vec<u8>>>,
}

pub struct TunWriter {
    id: u32,
    store: bool,
    tx: Mutex<Sender<Vec<u8>>>,
}

impl fmt::Display for TunFakeIO {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FakeIO({})", self.id)
    }
}

impl fmt::Display for TunReader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TunReader({})", self.id)
    }
}

impl fmt::Display for TunWriter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TunWriter({})", self.id)
    }
}

pub struct TunStatus {
    first: bool,
}

impl Error for TunError {
    fn description(&self) -> &str {
        "Generic Tun Error"
    }

    fn source(&self) -> Option<&(dyn Error + 'static)> {
        None
    }
}

impl fmt::Display for TunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Not Possible")
    }
}

#[async_trait]
impl Reader for TunReader {
    type Error = TunError;

    async fn read(&self, buf: &mut [u8], offset: usize) -> Result<usize, Self::Error> {
        match self.rx.lock().await.recv().await {
            Some(msg) => {
                let n = min(buf.len() - offset, msg.len());
                buf[offset..offset + n].copy_from_slice(&msg[..n]);
                debug!(
                    "dummy::TUN({}) : read ({}, {})",
                    self.id,
                    n,
                    hex::encode(&buf[offset..offset + n])
                );
                Ok(n)
            }
            None => Err(TunError::Disconnected),
        }
    }
}

#[async_trait]
impl Writer for TunWriter {
    type Error = TunError;

    async fn write(&self, src: &[u8]) -> Result<(), Self::Error> {
        debug!("dummy::TUN({}) : write ({}, {})", self.id, src.len(), hex::encode(src));
        if self.store {
            let m = src.to_owned();
            match self.tx.lock().await.send(m).await {
                Ok(_) => Ok(()),
                Err(_) => Err(TunError::Disconnected),
            }
        } else {
            Ok(())
        }
    }
}

#[async_trait]
impl Status for TunStatus {
    type Error = TunError;

    async fn event(&mut self) -> Result<TunEvent, Self::Error> {
        if self.first {
            self.first = false;
            return Ok(TunEvent::Up(1420));
        }

        loop {
            tokio::time::sleep(Duration::from_secs(60 * 60)).await;
        }
    }
}

impl Tun for TunTest {
    type Writer = TunWriter;
    type Reader = TunReader;
    type Error = TunError;
}

impl TunFakeIO {
    pub async fn write(&self, msg: Vec<u8>) {
        if self.store {
            self.tx.send(msg).await.unwrap();
        }
    }

    pub async fn read(&self) -> Vec<u8> {
        self.rx.lock().await.recv().await.unwrap()
    }
}

impl TunTest {
    pub fn create(store: bool) -> (TunFakeIO, TunReader, TunWriter, TunStatus) {
        let (tx1, rx1) = if store { channel(32) } else { channel(1) };
        let (tx2, rx2) = if store { channel(32) } else { channel(1) };

        let id: u32 = OsRng.gen();

        let fake = TunFakeIO {
            id,
            tx: tx1,
            rx: Mutex::new(rx2),
            store,
        };
        let reader = TunReader {
            id,
            rx: Mutex::new(rx1),
        };
        let writer = TunWriter {
            id,
            tx: Mutex::new(tx2),
            store,
        };
        let status = TunStatus { first: true };
        (fake, reader, writer, status)
    }
}

impl PlatformTun for TunTest {
    type Status = TunStatus;

    fn create(_name: &str) -> Result<(Vec<Self::Reader>, Self::Writer, Self::Status), Self::Error> {
        Err(TunError::Disconnected)
    }
}
