use async_trait::async_trait;
use std::{
    io::{self, ErrorKind},
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};

use byte_string::ByteStr;
use kcp::KcpResult;
use log::{debug, error, trace};
use tokio::{sync::mpsc, task::JoinHandle, time};

use crate::{
    context::Context,
    net::{AcceptOpts, UdpSocket},
    ServerAddr,
};

use super::{config::KcpConfig, session::KcpSessionManager, stream::KcpStream};

use super::super::{Acceptor, Connection, DummyPacket};

pub struct KcpListener {
    udp: Arc<UdpSocket>,
    accept_rx: mpsc::Receiver<(KcpStream, SocketAddr)>,
    task_watcher: JoinHandle<()>,
}

impl Drop for KcpListener {
    fn drop(&mut self) {
        self.task_watcher.abort();
    }
}

#[async_trait]
impl Acceptor for KcpListener {
    type TS = KcpStream;
    type PR = DummyPacket;
    type PW = DummyPacket;

    async fn accept(&mut self) -> io::Result<(Connection<Self::TS, Self::PR, Self::PW>, Option<ServerAddr>)> {
        match self.accept_rx.recv().await {
            Some((stream, addr)) => Ok((Connection::Stream(stream), Some(ServerAddr::SocketAddr(addr)))),
            None => Err(io::Error::new(ErrorKind::Other, "accept channel closed unexpectly")),
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.udp.local_addr()
    }
}

impl KcpListener {
    pub async fn create(
        config: KcpConfig,
        context: &Context,
        addr: &ServerAddr,
        accept_opts: AcceptOpts,
    ) -> KcpResult<KcpListener> {
        let udp = UdpSocket::listen_server_with_opts(context, addr, accept_opts).await?;
        Self::new(config, udp)
    }

    pub async fn bind(config: KcpConfig, addr: &SocketAddr) -> KcpResult<KcpListener> {
        let udp = UdpSocket::listen(addr).await?;
        Self::new(config, udp)
    }

    pub fn new(config: KcpConfig, udp: UdpSocket) -> KcpResult<KcpListener> {
        let udp = Arc::new(udp);
        let server_udp = udp.clone();

        let (accept_tx, accept_rx) = mpsc::channel(1024 /* backlogs */);
        let task_watcher = tokio::spawn(async move {
            let (close_tx, mut close_rx) = mpsc::channel(64);

            let mut sessions = KcpSessionManager::new();
            let mut packet_buffer = [0u8; 65536];
            loop {
                tokio::select! {
                    peer_addr = close_rx.recv() => {
                        let peer_addr = peer_addr.expect("close_tx closed unexpectly");
                        sessions.close_peer(peer_addr);
                        trace!("session peer_addr: {} removed", peer_addr);
                    }

                    recv_res = udp.recv_from(&mut packet_buffer) => {
                        match recv_res {
                            Err(err) => {
                                error!("udp.recv_from failed, error: {}", err);
                                time::sleep(Duration::from_secs(1)).await;
                            }
                            Ok((n, peer_addr)) => {
                                let packet = &mut packet_buffer[..n];

                                log::trace!("received peer: {}, {:?}", peer_addr, ByteStr::new(packet));

                                let mut conv = kcp::get_conv(packet);
                                if conv == 0 {
                                    // Allocate a conv for client.
                                    conv = sessions.alloc_conv();
                                    debug!("allocate {} conv for peer: {}", conv, peer_addr);

                                    kcp::set_conv(packet, conv);
                                }

                                let sn = kcp::get_sn(packet);

                                let session = match sessions.get_or_create(&config, conv, sn, &udp, peer_addr, &close_tx).await {
                                    Ok((s, created)) => {
                                        if created {
                                            // Created a new session, constructed a new accepted client
                                            let stream = KcpStream::with_session(s.clone());
                                            if let Err(..) = accept_tx.try_send((stream, peer_addr)) {
                                                debug!("failed to create accepted stream due to channel failure");

                                                // remove it from session
                                                sessions.close_peer(peer_addr);
                                                continue;
                                            }
                                        } else {
                                            let session_conv = s.conv().await;
                                            if session_conv != conv {
                                                debug!("received peer: {} with conv: {} not match with session conv: {}",
                                                       peer_addr,
                                                       conv,
                                                       session_conv);
                                                continue;
                                            }
                                        }

                                        s
                                    },
                                    Err(err) => {
                                        error!("failed to create session, error: {}, peer: {}, conv: {}", err, peer_addr, conv);
                                        continue;
                                    }
                                };

                                // let mut kcp = session.kcp_socket().lock().await;
                                // if let Err(err) = kcp.input(packet) {
                                //     error!("kcp.input failed, peer: {}, conv: {}, error: {}, packet: {:?}", peer_addr, conv, err, ByteStr::new(packet));
                                // }
                                session.input(packet).await;
                            }
                        }
                    }
                }
            }
        });

        Ok(KcpListener {
            udp: server_udp,
            accept_rx,
            task_watcher,
        })
    }
}

#[cfg(test)]
mod test {
    use super::super::stream::KcpStream;
    use super::*;
    use futures::future;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn multi_echo() {
        let _ = env_logger::try_init();

        let config = KcpConfig::default();

        let addr = "127.0.0.1:0".parse::<SocketAddr>().unwrap();
        let mut listener = KcpListener::bind(config.clone(), &addr).await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept_stream().await.unwrap();

                tokio::spawn(async move {
                    let mut buffer = [0u8; 8192];
                    while let Ok(n) = stream.read(&mut buffer).await {
                        if n == 0 {
                            break;
                        }

                        let data = &buffer[..n];
                        stream.write_all(data).await.unwrap();
                        stream.flush().await.unwrap();
                    }
                });
            }
        });

        let mut vfut = Vec::new();

        for _ in 0..100 {
            vfut.push(async move {
                let mut stream = KcpStream::connect(&config, &server_addr).await.unwrap();

                for _ in 0..20 {
                    const SEND_BUFFER: &[u8] = b"HELLO WORLD";
                    stream.write_all(SEND_BUFFER).await.unwrap();
                    stream.flush().await.unwrap();

                    let mut buffer = [0u8; 1024];
                    let n = stream.recv(&mut buffer).await.unwrap();
                    assert_eq!(SEND_BUFFER, &buffer[..n]);
                }
            });
        }

        future::join_all(vfut).await;
    }
}
