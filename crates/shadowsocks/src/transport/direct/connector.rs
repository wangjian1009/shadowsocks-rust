use std::{io, sync::Arc};

use crate::{net::ConnectOpts, ServerAddr};

use async_trait::async_trait;

use super::super::Connector;

use crate::context::Context;

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
    #[cfg(feature = "rate-limit")]
    type TS = super::super::RateLimitedStream<crate::net::TcpStream>;
    #[cfg(not(feature = "rate-limit"))]
    type TS = crate::net::TcpStream;

    async fn connect(&self, addr: &ServerAddr, connect_opts: &ConnectOpts) -> io::Result<Self::TS> {
        if let Some(context) = self.context.as_ref() {
            let stream = crate::net::TcpStream::connect_server_with_opts(context, addr, &connect_opts).await?;

            #[cfg(feature = "rate-limit")]
            let stream = Self::TS::from_stream(stream, None);

            Ok(stream)
        } else {
            match addr {
                ServerAddr::SocketAddr(ref addr) => {
                    let stream = crate::net::TcpStream::connect_with_opts(addr, &connect_opts).await?;

                    #[cfg(feature = "rate-limit")]
                    let stream = Self::TS::from_stream(stream, None);

                    Ok(stream)
                }
                ServerAddr::DomainName(..) => Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!("TcpConnector not support tcp connect to domain address"),
                )),
            }
        }
    }
}
