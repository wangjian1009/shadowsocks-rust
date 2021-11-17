//! Shadowsocks TCP server

use rand;
use std::{
    future::Future,
    io::{self, ErrorKind},
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};

use log::{debug, error, info, trace, warn};
use shadowsocks::{
    crypto::v1::CipherKind,
    net::{AcceptOpts, TcpStream as OutboundTcpStream},
    relay::{
        socks5::{Address, Error as Socks5Error},
        tcprelay::{utils::copy_encrypted_bidirectional, ProxyServerStream},
    },
    ProxyListener,
    ServerConfig,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream as TokioTcpStream,
    time,
};

use crate::net::{utils::ignore_until_end, MonProxyStream};

use super::{connection::ConnectionInfo, context::ServiceContext};

pub struct TcpServer {
    context: Arc<ServiceContext>,
    accept_opts: AcceptOpts,
}

impl TcpServer {
    pub fn new(context: Arc<ServiceContext>, accept_opts: AcceptOpts) -> TcpServer {
        TcpServer { context, accept_opts }
    }

    pub async fn run(self, svr_cfg: &ServerConfig) -> io::Result<()> {
        let listener = ProxyListener::bind_with_opts(self.context.context(), svr_cfg, self.accept_opts).await?;

        info!(
            "shadowsocks tcp server listening on {}, inbound address {}",
            listener.local_addr().expect("listener.local_addr"),
            svr_cfg.addr()
        );

        loop {
            let flow_stat = self.context.flow_stat();
            let connection_stat = self.context.connection_stat();

            let (local_stream, peer_addr) =
                match listener.accept_map(|s| MonProxyStream::from_stream(s, flow_stat)).await {
                    Ok(s) => s,
                    Err(err) => {
                        error!("tcp server accept failed with error: {}", err);
                        time::sleep(Duration::from_secs(1)).await;
                        continue;
                    }
                };

            let conn = connection_stat.add_in_connection(peer_addr).await;

            let client = TcpServerClient {
                context: self.context.clone(),
                method: svr_cfg.method(),
                conn,
                peer_addr,
                stream: local_stream,
                timeout: svr_cfg.timeout(),
                request_recv_timeout: svr_cfg.request_recv_timeout().clone(),
            };

            let connection_stat = connection_stat.clone();
            tokio::spawn(async move {
                let conn_id = client.conn.id;

                if let Err(err) = client.serve().await {
                    debug!("tcp server stream aborted with error: {}", err);
                }

                connection_stat.remove_in_connection(&conn_id).await
            });
        }
    }
}

#[inline]
async fn timeout_fut<F, R>(duration: Option<Duration>, f: F) -> io::Result<R>
where
    F: Future<Output = io::Result<R>>,
{
    match duration {
        None => f.await,
        Some(d) => match time::timeout(d, f).await {
            Ok(o) => o,
            Err(..) => Err(ErrorKind::TimedOut.into()),
        },
    }
}

struct TcpServerClient {
    context: Arc<ServiceContext>,
    method: CipherKind,
    conn: Arc<ConnectionInfo>,
    peer_addr: SocketAddr,
    stream: ProxyServerStream<MonProxyStream<TokioTcpStream>>,
    timeout: Option<Duration>,
    request_recv_timeout: Duration,
}

impl TcpServerClient {
    async fn serve(mut self) -> io::Result<()> {
        let connection_stat = self.context.connection_stat();

        let request_timeout = self.request_recv_timeout
            + Duration::from_secs(rand::random::<u64>() % self.request_recv_timeout.as_secs());

        let target_addr = match time::timeout(request_timeout, Address::read_from(&mut self.stream)).await {
            Ok(Ok(a)) => a,
            Ok(Err(Socks5Error::IoError(ref err))) if err.kind() == ErrorKind::UnexpectedEof => {
                debug!(
                    "handshake failed, received EOF before a complete target Address, peer: {}",
                    self.peer_addr
                );
                return Ok(());
            }
            Ok(Err(err)) => {
                // https://github.com/shadowsocks/shadowsocks-rust/issues/292
                //
                // Keep connection open.
                warn!(
                    "handshake failed, maybe wrong method or key, or under reply attacks. peer: {}, error: {}",
                    self.peer_addr, err
                );

                // Unwrap and get the plain stream.
                // Otherwise it will keep reporting decryption error before reaching EOF.
                //
                // Note: This will drop all data in the decryption buffer, which is no going back.
                let mut stream = self.stream.into_inner();

                let res = ignore_until_end(&mut stream).await;

                trace!(
                    "silent-drop peer: {} is now closing with result {:?}",
                    self.peer_addr,
                    res
                );

                return Ok(());
            }
            Err(err) => {
                warn!("handshake timeout. peer: {}, error: {}", self.peer_addr, err);
                return Ok(());
            }
        };
        // self.conn.lock().await.remote_addr

        trace!(
            "accepted tcp client connection {}, establishing tunnel to {}",
            self.peer_addr,
            target_addr
        );

        if self.context.check_outbound_blocked(&target_addr).await {
            error!(
                "tcp client {} outbound {} blocked by ACL rules",
                self.peer_addr, target_addr
            );
            return Ok(());
        }

        let mut remote_stream = match timeout_fut(
            self.timeout,
            OutboundTcpStream::connect_remote_with_opts(
                self.context.context_ref(),
                &target_addr,
                self.context.connect_opts_ref(),
            ),
        )
        .await
        {
            Ok(s) => s,
            Err(err) => {
                error!(
                    "tcp tunnel {} -> {} connect failed, error: {}",
                    self.peer_addr, target_addr, err
                );
                return Err(err);
            }
        };

        let _out_guard = connection_stat.add_out_connection();

        // https://github.com/shadowsocks/shadowsocks-rust/issues/232
        //
        // Protocols like FTP, clients will wait for servers to send Welcome Message without sending anything.
        //
        // Wait at most 500ms, and then sends handshake packet to remote servers.
        if self.context.connect_opts_ref().tcp.fastopen {
            let mut buffer = [0u8; 8192];
            match time::timeout(Duration::from_millis(500), self.stream.read(&mut buffer)).await {
                Ok(Ok(0)) => {
                    // EOF. Just terminate right here.
                    return Ok(());
                }
                Ok(Ok(n)) => {
                    // Send the first packet.
                    timeout_fut(self.timeout, remote_stream.write_all(&buffer[..n])).await?;
                }
                Ok(Err(err)) => return Err(err),
                Err(..) => {
                    // Timeout. Send handshake to server.
                    timeout_fut(self.timeout, remote_stream.write(&[])).await?;

                    trace!(
                        "tcp tunnel {} -> {} sent TFO connect without data",
                        self.peer_addr,
                        target_addr
                    );
                }
            }
        }

        debug!(
            "established tcp tunnel {} <-> {} with {:?}",
            self.peer_addr,
            target_addr,
            self.context.connect_opts_ref()
        );

        match copy_encrypted_bidirectional(self.method, &mut self.stream, &mut remote_stream).await {
            Ok((rn, wn)) => {
                trace!(
                    "tcp tunnel {} <-> {} closed, L2R {} bytes, R2L {} bytes",
                    self.peer_addr,
                    target_addr,
                    rn,
                    wn
                );
            }
            Err(err) => {
                trace!(
                    "tcp tunnel {} <-> {} closed with error: {}",
                    self.peer_addr,
                    target_addr,
                    err
                );
            }
        }

        Ok(())
    }
}
