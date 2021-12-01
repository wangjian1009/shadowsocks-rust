use byteorder::{BigEndian, ByteOrder};
use bytes::{BufMut, BytesMut};
use futures::future::{self, Either};
use log::{error, info};
use shadowsocks_service::local::dns::NameServerAddr;
use std::{
    fmt::Debug,
    fs,
    io::{self, ErrorKind},
    net::{IpAddr, SocketAddr},
    path::PathBuf,
};

use trust_dns_resolver::proto::{error::ProtoError, op::Message};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpListener,
    sync::Mutex,
    time::{self, Duration},
};

#[cfg(unix)]
use tokio::net::UnixListener;

use super::upstream::DnsClient;

pub struct HostDns {
    local_addr: NameServerAddr,
    remote_addrs: Mutex<Vec<SocketAddr>>,
    base_query_timeout: Duration,
    base_query_try: usize,
}

impl HostDns {
    pub fn new(local_addr: NameServerAddr) -> HostDns {
        HostDns {
            local_addr,
            remote_addrs: Mutex::new(vec![]),
            base_query_timeout: Duration::from_secs(5),
            base_query_try: 1,
        }
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

    #[allow(unused_assignments)]
    pub async fn update_servers(&self, servers: Vec<&str>) {
        log::info!("host dns update host dns: {:?}", servers);

        let mut new_addrs: Vec<SocketAddr> = vec![];

        for str_addr in servers.iter() {
            match str_addr.parse::<SocketAddr>() {
                Ok(sock_addr) => {
                    new_addrs.push(sock_addr);
                }
                Err(_err) => match str_addr.parse::<IpAddr>() {
                    Ok(ip) => new_addrs.push(SocketAddr::new(ip, 53)),
                    Err(err) => {
                        error!("host dns update host dns: parse {} fail, {}", str_addr, err);
                    }
                },
            };
        }

        let mut guard_addrs = self.remote_addrs.lock().await;

        log::info!("host dns update host dns: {:?} ==> {:?}", guard_addrs, new_addrs);

        *guard_addrs = new_addrs;
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

            let servers = self.get_servers().await;

            if servers.is_empty() {
                error!("host dns TCP accept success, no upstream");
                continue;
            } else {
                tokio::spawn(HostDns::handle_stream(
                    stream,
                    peer_addr,
                    servers,
                    self.base_query_timeout,
                    self.base_query_try,
                ));
            }
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

            let servers = self.get_servers().await;

            if servers.is_empty() {
                error!("host dns TCP accept success, no upstream");
                continue;
            } else {
                tokio::spawn(HostDns::handle_stream(
                    stream,
                    peer_addr,
                    servers,
                    self.base_query_timeout,
                    self.base_query_try,
                ));
            }
        }
    }

    async fn run_udp_server(&self, _bind_addr: &SocketAddr) -> io::Result<()> {
        Ok(())
    }

    async fn handle_stream<T, AddrT>(
        mut stream: T,
        peer_addr: AddrT,
        servers: Vec<SocketAddr>,
        base_query_timeout: Duration,
        base_query_try: usize,
    ) -> io::Result<()>
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

            let mut respond_message: Option<Message> = None;
            let mut last_error: Option<ProtoError> = None;

            for server in (&servers).into_iter() {
                respond_message = match HostDns::resolve(&message, &server, base_query_timeout, base_query_try).await {
                    Ok(respond_message) => Some(respond_message),
                    Err(err) => {
                        last_error = Some(err);
                        continue;
                    }
                }
            }

            match respond_message {
                None => match last_error {
                    None => return Err(io::Error::new(ErrorKind::Other, "no any response")),
                    Some(err) => return Err(io::Error::new(ErrorKind::Other, err.clone())),
                },
                Some(respond_message) => {
                    let mut buf = respond_message.to_vec()?;
                    let length = buf.len();
                    buf.resize(length + 2, 0);
                    buf.copy_within(..length, 2);
                    BigEndian::write_u16(&mut buf[..2], length as u16);

                    stream.write_all(&buf).await?;
                }
            }
        }

        Ok(())
    }

    async fn resolve(
        msg: &Message,
        server: &SocketAddr,
        base_query_timeout: Duration,
        base_query_try: usize,
    ) -> Result<Message, ProtoError> {
        let udp_query = HostDns::resolve_udp(msg, server, base_query_timeout, base_query_try);
        let tcp_query = async move {
            // Send TCP query after 500ms, because UDP will always return faster than TCP, there is no need to send queries simutaneously
            time::sleep(Duration::from_millis(500)).await;

            HostDns::resolve_tcp(msg, server, base_query_timeout, base_query_try).await
        };

        tokio::pin!(udp_query);
        tokio::pin!(tcp_query);

        match future::select(udp_query, tcp_query).await {
            Either::Left((Ok(m), ..)) => Ok(m),
            Either::Left((Err(..), next)) => next.await.map_err(From::from),
            Either::Right((Ok(m), ..)) => Ok(m),
            Either::Right((Err(..), next)) => next.await.map_err(From::from),
        }
    }

    async fn resolve_udp(
        msg: &Message,
        server: &SocketAddr,
        timeout: Duration,
        retry_count: usize,
    ) -> Result<Message, ProtoError> {
        let mut last_err: Option<ProtoError> = None;

        for _ in 0..retry_count {
            let mut client = match DnsClient::connect_udp(server).await {
                Ok(client) => client,
                Err(error) => {
                    last_err = Some(error.into());
                    continue;
                }
            };

            let res = match client.lookup_timeout(msg.clone(), timeout).await {
                Ok(msg) => msg,
                Err(error) => {
                    last_err = Some(error.into());
                    continue;
                }
            };

            return Ok(res);
        }

        Err(last_err.unwrap())
    }

    async fn resolve_tcp(
        msg: &Message,
        server: &SocketAddr,
        timeout: Duration,
        retry_count: usize,
    ) -> Result<Message, ProtoError> {
        let mut last_err: Option<ProtoError> = None;

        for _ in 0..retry_count {
            let mut client = match DnsClient::connect_tcp(server).await {
                Ok(client) => client,
                Err(error) => {
                    last_err = Some(error.into());
                    continue;
                }
            };

            let res = match client.lookup_timeout(msg.clone(), timeout).await {
                Ok(msg) => msg,
                Err(error) => {
                    last_err = Some(error.into());
                    continue;
                }
            };

            return Ok(res);
        }

        Err(last_err.unwrap())
    }

    async fn get_servers(&self) -> Vec<SocketAddr> {
        (*self.remote_addrs.lock().await).clone()
    }
}
