use async_trait::async_trait;
use std::{io, sync::Arc};
use tokio::{sync::mpsc, task::JoinHandle};

use super::{PacketMutWrite, PacketWrite};
use crate::ServerAddr;

struct Packet {
    addr: ServerAddr,
    buf: Vec<u8>,
}

#[derive(Clone)]
pub struct MutPacketWriter {
    sender: mpsc::Sender<Packet>,
    abortable: Arc<JoinHandle<()>>,
}

impl MutPacketWriter {
    pub fn new<PW: PacketMutWrite + 'static>(mut inner: PW, chanel_size: usize) -> Self {
        let (tx, mut rx) = mpsc::channel::<Packet>(chanel_size);

        let handler = tokio::spawn(async move {
            while let Some(packet) = rx.recv().await {
                match inner.write_to_mut(packet.buf.as_slice(), &packet.addr).await {
                    Ok(()) => {}
                    Err(err) => {
                        match err.kind() {
                            io::ErrorKind::UnexpectedEof => {}
                            _ => {
                                tracing::error!("MutPacketWrite: write to inner error: {}", err);
                            }
                        }
                        rx.close();
                        break;
                    }
                }
                tokio::task::yield_now().await;
            }
        });

        Self {
            sender: tx,
            abortable: Arc::new(handler),
        }
    }

    pub fn new_boxed(mut inner: Box<dyn PacketMutWrite>, chanel_size: usize) -> Self {
        let (tx, mut rx) = mpsc::channel::<Packet>(chanel_size);

        let handler = tokio::spawn(async move {
            while let Some(packet) = rx.recv().await {
                match inner.write_to_mut(packet.buf.as_slice(), &packet.addr).await {
                    Ok(()) => {}
                    Err(err) => {
                        match err.kind() {
                            io::ErrorKind::UnexpectedEof => {}
                            _ => {
                                tracing::error!("MutPacketWrite: write to inner error: {}", err);
                            }
                        }
                        rx.close();
                        break;
                    }
                }
                tokio::task::yield_now().await;
            }
        });

        Self {
            sender: tx,
            abortable: Arc::new(handler),
        }
    }
}

impl Drop for MutPacketWriter {
    fn drop(&mut self) {
        self.abortable.abort()
    }
}

#[async_trait]
impl PacketWrite for MutPacketWriter {
    async fn write_to(&self, buf: &[u8], addr: &ServerAddr) -> io::Result<()> {
        match self
            .sender
            .send(Packet {
                addr: addr.clone(),
                buf: buf.to_owned(),
            })
            .await
        {
            Ok(()) => Ok(()),
            Err(err) => Err(io::Error::new(io::ErrorKind::Other, format!("{}", err))),
        }
    }
}

#[async_trait]
impl PacketMutWrite for MutPacketWriter {
    async fn write_to_mut(&mut self, buf: &[u8], addr: &ServerAddr) -> io::Result<()> {
        self.write_to(buf, addr).await
    }
}
