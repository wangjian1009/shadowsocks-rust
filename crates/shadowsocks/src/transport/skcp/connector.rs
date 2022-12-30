use async_trait::async_trait;
use std::io;
use std::sync::Arc;

use crate::context::Context;
use crate::net::{ConnectOpts, UdpSocket};
use crate::ServerAddr;

use super::{new_error, session::KcpSession, skcp::KcpSocket, SkcpConfig, SkcpStream};

use super::super::Connector;

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

    async fn connect(&self, addr: &ServerAddr, connect_opts: &ConnectOpts) -> io::Result<Self::TS> {
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
        let header = self.config.create_header().map(|e| Arc::new(e));
        let security = self.config.create_security().map(|e| Arc::new(e));
        let socket = KcpSocket::new(
            self.config.as_ref(),
            conv,
            udp,
            remote_addr,
            self.config.stream,
            header.clone(),
            security.clone(),
        )?;

        let session = KcpSession::new_shared(socket, header, security, self.config.session_expire, None);

        Ok(SkcpStream::with_session(session))
    }
}
