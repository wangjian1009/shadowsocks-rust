use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

use crate::{
    net::{AddrFamily, ConnectOpts, UdpSocket},
    ServerAddr,
};

use async_trait::async_trait;

use super::super::{Connection, Connector};

use crate::{context::Context, net::Destination};

pub struct TcpConnector {
    context: Option<Arc<Context>>,
}

impl TcpConnector {
    pub fn new(context: Option<Arc<Context>>) -> TcpConnector {
        TcpConnector { context }
    }
}

#[async_trait]
impl Connector for TcpConnector {
    type PR = Arc<UdpSocket>;
    type PW = Arc<UdpSocket>;
    #[cfg(feature = "rate-limit")]
    type TS = super::super::RateLimitedStream<crate::net::TcpStream>;
    #[cfg(not(feature = "rate-limit"))]
    type TS = crate::net::TcpStream;

    async fn connect(
        &self,
        destination: &Destination,
        connect_opts: &ConnectOpts,
    ) -> io::Result<Connection<Self::TS, Self::PR, Self::PW>> {
        match &destination {
            Destination::Tcp(ref addr) => {
                if let Some(context) = self.context.as_ref() {
                    let stream = crate::net::TcpStream::connect_server_with_opts(context, addr, &connect_opts).await?;

                    #[cfg(feature = "rate-limit")]
                    let stream = Self::TS::from_stream(stream, None);

                    Ok(Connection::Stream(stream))
                } else {
                    match addr {
                        ServerAddr::SocketAddr(ref addr) => {
                            let stream = crate::net::TcpStream::connect_with_opts(addr, &connect_opts).await?;

                            #[cfg(feature = "rate-limit")]
                            let stream = Self::TS::from_stream(stream, None);

                            Ok(Connection::Stream(stream))
                        }
                        ServerAddr::DomainName(..) => Err(io::Error::new(
                            io::ErrorKind::Other,
                            format!("TcpConnector not support tcp connect to domain address"),
                        )),
                    }
                }
            }
            Destination::Udp(ref addr) => {
                let socket = match addr {
                    ServerAddr::DomainName(..) => {
                        if let Some(context) = self.context.as_ref() {
                            UdpSocket::connect_server_with_opts(context, addr, &connect_opts).await?
                        } else {
                            return Err(io::Error::new(
                                io::ErrorKind::Other,
                                format!("TcpConnector not support tcp connect to domain address"),
                            ));
                        }
                    }
                    ServerAddr::SocketAddr(addr) => match addr {
                        SocketAddr::V4(addr_v4) => {
                            if addr_v4.port() == 0 || addr_v4.ip() == &Ipv4Addr::UNSPECIFIED {
                                UdpSocket::connect_any_with_opts(AddrFamily::Ipv4, &connect_opts).await?
                            } else {
                                UdpSocket::connect_with_opts(addr, &connect_opts).await?
                            }
                        }
                        SocketAddr::V6(addr_v6) => {
                            if addr_v6.port() == 0 || addr_v6.ip() == &Ipv6Addr::UNSPECIFIED {
                                UdpSocket::connect_any_with_opts(AddrFamily::Ipv6, &connect_opts).await?
                            } else {
                                UdpSocket::connect_with_opts(addr, &connect_opts).await?
                            }
                        }
                    },
                };

                let local_addr = Destination::Udp(ServerAddr::SocketAddr(socket.local_addr()?));
                let r = Arc::new(socket);
                let w = r.clone();
                Ok(Connection::Packet { r, w, local_addr })
            }
            #[cfg(unix)]
            Destination::Unix(_addr) => Err(io::Error::new(
                io::ErrorKind::Other,
                format!("TcpConnector not support domain socket"),
            )),
        }
    }
}
