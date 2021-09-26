use byteorder::{BigEndian, ByteOrder};
use bytes::{BufMut, BytesMut};
use futures::future::{self, Either};
use log::{error, info, trace};
use rand::{thread_rng, Rng};
use shadowsocks_service::{local::dns::NameServerAddr, shadowsocks::config::Mode};
use std::{
    fmt::Debug,
    fs,
    io::{self, ErrorKind},
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
};

use trust_dns_resolver::proto::op::{header::MessageType, response_code::ResponseCode, Message, OpCode, Query};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpListener,
    time::{self, Duration},
};

#[cfg(unix)]
use tokio::net::UnixListener;

pub struct HostDns {
    mode: Mode,
    local_addr: NameServerAddr,
    remote_addr: Option<Arc<SocketAddr>>,
}

impl HostDns {
    pub fn new(local_addr: NameServerAddr, remote_addr: Option<SocketAddr>) -> HostDns {
        HostDns {
            mode: Mode::UdpOnly,
            local_addr,
            remote_addr: match remote_addr {
                Some(addr) => Some(Arc::new(addr)),
                None => None,
            },
        }
    }

    /// Set remote server mode
    pub fn set_mode(&mut self, mode: Mode) {
        self.mode = mode;
    }

    /// Run server
    pub async fn run(&self) -> io::Result<()> {
        match self.local_addr {
            NameServerAddr::SocketAddr(ref local_addr) => {
                let tcp_fut = self.run_tcp_server(local_addr);
                let udp_fut = self.run_udp_server(local_addr);

                tokio::pin!(tcp_fut, udp_fut);

                match future::select(tcp_fut, udp_fut).await {
                    Either::Left((res, ..)) => res,
                    Either::Right((res, ..)) => res,
                }
            }
            #[cfg(unix)]
            NameServerAddr::UnixSocketAddr(ref path) => self.run_unix_stream_server(path).await,
        }
    }

    #[cfg(unix)]
    async fn run_unix_stream_server(&self, path: &PathBuf) -> io::Result<()> {
        match fs::remove_file(path) {
            Ok(_) => {}
            Err(ref err) if err.kind() == ErrorKind::NotFound => {}
            Err(err) => {
                error!("host dns unixstream listening: remote {:?} error, {}", path, err);
                return Err(err);
            }
        }

        let listener: UnixListener = UnixListener::bind(path)?;

        info!("host dns unixstream listening on {:?}", path);

        loop {
            let (stream, peer_addr) = match listener.accept().await {
                Ok(s) => s,
                Err(err) => {
                    error!("accept failed with error: {}", err);
                    time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
            };

            info!("host dns unixstream accept one from {:?}", peer_addr);

            match &self.remote_addr {
                Some(remote_addr) => tokio::spawn(HostDns::handle_stream(stream, peer_addr, remote_addr.clone())),
                None => {
                    error!("host dns TCP accept success, no upstream");
                    continue;
                }
            };
        }
    }

    async fn run_tcp_server(&self, bind_addr: &SocketAddr) -> io::Result<()> {
        let listener = TcpListener::bind(bind_addr).await?;

        info!("host dns TCP listening on {}", bind_addr);

        loop {
            let (stream, peer_addr) = match listener.accept().await {
                Ok(s) => s,
                Err(err) => {
                    error!("accept failed with error: {}", err);
                    time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
            };

            match &self.remote_addr {
                Some(remote_addr) => tokio::spawn(HostDns::handle_stream(stream, peer_addr, remote_addr.clone())),
                None => {
                    error!("host dns TCP accept success, no upstream");
                    continue;
                }
            };
        }
    }

    async fn run_udp_server(&self, bind_addr: &SocketAddr) -> io::Result<()> {
        Ok(())
    }

    async fn handle_stream<T, AddrT>(mut stream: T, peer_addr: AddrT, remote_addr: Arc<SocketAddr>) -> io::Result<()>
    where
        T: AsyncRead + AsyncWrite + Unpin,
        AddrT: Debug,
    {
        let mut length_buf = [0u8; 2];
        let mut message_buf = BytesMut::new();
        loop {
            match stream.read_exact(&mut length_buf).await {
                Ok(..) => {}
                Err(ref err) if err.kind() == ErrorKind::UnexpectedEof => {
                    break;
                }
                Err(err) => {
                    error!("host dns stream {:?} read length failed, error: {}", peer_addr, err);
                    return Err(err);
                }
            }

            let length = BigEndian::read_u16(&length_buf) as usize;

            message_buf.clear();
            message_buf.reserve(length);
            unsafe {
                message_buf.advance_mut(length);
            }

            match stream.read_exact(&mut message_buf).await {
                Ok(..) => {}
                Err(err) => {
                    error!("host dns stream {:?} read message failed, error: {}", peer_addr, err);
                    return Err(err);
                }
            }

            let message = match Message::from_vec(&message_buf) {
                Ok(m) => m,
                Err(err) => {
                    error!("host dns stream {:?} parse message failed, error: {}", peer_addr, err);
                    return Err(err.into());
                }
            };

            let client = DnsClient { attempts: 2 };
            let respond_message = match client.resolve(message, &remote_addr).await {
                Ok(m) => m,
                Err(err) => {
                    error!("host dns stream {:?} lookup error: {}", peer_addr, err);
                    return Err(err);
                }
            };

            let mut buf = respond_message.to_vec()?;
            let length = buf.len();
            buf.resize(length + 2, 0);
            buf.copy_within(..length, 2);
            BigEndian::write_u16(&mut buf[..2], length as u16);

            stream.write_all(&buf).await?;
        }

        trace!("host dns stream connection {:?} closed", peer_addr);

        Ok(())
    }
}

struct DnsClient {
    attempts: usize,
}

impl DnsClient {
    fn new() -> DnsClient {
        DnsClient { attempts: 2 }
    }

    async fn resolve(&self, request: Message, remote_addr: &SocketAddr) -> io::Result<Message> {
        let mut message = Message::new();
        message.set_id(request.id());
        message.set_recursion_desired(true);
        message.set_recursion_available(true);
        message.set_message_type(MessageType::Response);

        if !request.recursion_desired() {
            // RD is required by default. Otherwise it may not get valid respond from remote servers

            message.set_recursion_desired(false);
            message.set_response_code(ResponseCode::NotImp);
        } else if request.op_code() != OpCode::Query || request.message_type() != MessageType::Query {
            // Other ops are not supported

            message.set_response_code(ResponseCode::NotImp);
        } else if request.query_count() > 0 {
            // Make queries according to ACL rules

            let r = self.lookup_local(&request.queries()[0], remote_addr).await;
            if let Ok(result) = r {
                for rec in result.answers() {
                    trace!("native dns answer: {:?}", rec);
                }
                message = result;
                message.set_id(request.id());
            } else {
                message.set_response_code(ResponseCode::ServFail);
            }
        }
        Ok(message)
    }

    async fn lookup_local(&self, query: &Query, local_addr: &SocketAddr) -> io::Result<Message> {
        let mut last_err = io::Error::new(ErrorKind::InvalidData, "resolve empty");

        for _ in 0..self.attempts {
            match self.lookup_local_inner(query, local_addr).await {
                Ok(m) => {
                    return Ok(m);
                }
                Err(err) => last_err = err,
            }
        }

        Err(last_err)
    }

    async fn lookup_local_inner(&self, query: &Query, local_addr: &SocketAddr) -> io::Result<Message> {
        let mut message = Message::new();
        message.set_id(thread_rng().gen());
        message.set_recursion_desired(true);
        message.add_query(query.clone());

        // let udp_query = self
        //     .client_cache
        //     .lookup_udp_local(ns, message.clone(), self.context.connect_opts_ref());
        // let tcp_query = async move {
        //     // Send TCP query after 500ms, because UDP will always return faster than TCP, there is no need to send queries simutaneously
        //     time::sleep(Duration::from_millis(500)).await;

        //     self.client_cache
        //         .lookup_tcp_local(ns, message, self.context.connect_opts_ref())
        //         .await
        // };

        // tokio::pin!(udp_query);
        // tokio::pin!(tcp_query);

        // match future::select(udp_query, tcp_query).await {
        //     Either::Left((Ok(m), ..)) => Ok(m),
        //     Either::Left((Err(..), next)) => next.await.map_err(From::from),
        //     Either::Right((Ok(m), ..)) => Ok(m),
        //     Either::Right((Err(..), next)) => next.await.map_err(From::from),
        // }
        Err(io::Error::new(ErrorKind::InvalidData, "resolve empty"))
    }
}
