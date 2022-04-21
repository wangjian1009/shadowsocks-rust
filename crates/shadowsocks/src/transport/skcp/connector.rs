use async_trait::async_trait;
use std::io;
use std::sync::Arc;

use crate::context::Context;
use crate::net::{ConnectOpts, Destination, UdpSocket};
use crate::ServerAddr;

use super::{new_error, session::KcpSession, skcp::KcpSocket, SkcpConfig, SkcpStream};

use super::super::{Connection, Connector, DummyPacket};

pub struct SkcpConnector {
    context: Option<Arc<Context>>,
    config: Arc<SkcpConfig>,
}

impl SkcpConnector {
    pub fn new(context: Option<Arc<Context>>, config: Arc<SkcpConfig>) -> Self {
        Self { context, config }
    }
}

#[async_trait]
impl Connector for SkcpConnector {
    type TS = SkcpStream;
    type PR = DummyPacket;
    type PW = DummyPacket;

    async fn connect(
        &self,
        destination: &Destination,
        connect_opts: &ConnectOpts,
    ) -> io::Result<Connection<Self::TS, Self::PR, Self::PW>> {
        match destination {
            Destination::Tcp(addr) => {
                let (remote_addr, udp) = match self.context.as_ref() {
                    Some(context) => UdpSocket::create_for_connect_to(context, addr, &connect_opts).await?,
                    None => match addr {
                        ServerAddr::SocketAddr(ref addr) => (
                            addr.clone(),
                            UdpSocket::connect_any_with_opts(addr, &connect_opts).await?,
                        ),
                        ServerAddr::DomainName(..) => {
                            return Err(new_error("not support tcp connect to domain address(no context)"))
                        }
                    },
                };

                let udp = Arc::new(udp);
                let conv = rand::random();
                let socket = KcpSocket::new(self.config.as_ref(), conv, udp, remote_addr, self.config.stream)?;

                let session = KcpSession::new_shared(socket, self.config.session_expire, None);

                Ok(Connection::Stream(SkcpStream::with_session(session)))
            }
            Destination::Udp(..) => Err(new_error("not support connect Udp connection")),
            #[cfg(unix)]
            Destination::Unix(..) => Err(new_error("not support connect Unix stream")),
        }
    }
}
