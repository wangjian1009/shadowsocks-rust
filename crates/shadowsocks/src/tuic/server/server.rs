use super::{connection::Connection, UdpSocketCreator};
use futures_util::StreamExt;
use quinn::{Endpoint, EndpointConfig, Incoming, ServerConfig};
use std::{collections::HashSet, io::Result, sync::Arc, time::Duration};

pub struct Server {
    incoming: Incoming,
    token: Arc<HashSet<[u8; 32]>>,
    authentication_timeout: Duration,
    udp_socket_creator: Arc<Box<dyn UdpSocketCreator>>,
}

impl Server {
    pub fn init(
        config: ServerConfig,
        socket: std::net::UdpSocket,
        token: HashSet<[u8; 32]>,
        auth_timeout: Duration,
        udp_socket_creator: Box<dyn UdpSocketCreator>,
    ) -> Result<Self> {
        let (_, incoming) = Endpoint::new(EndpointConfig::default(), Some(config), socket)?;

        Ok(Self {
            incoming,
            token: Arc::new(token),
            authentication_timeout: auth_timeout,
            udp_socket_creator: Arc::new(udp_socket_creator),
        })
    }

    pub async fn run(mut self) {
        while let Some(conn) = self.incoming.next().await {
            let token = self.token.clone();

            tokio::spawn(Connection::handle(
                conn,
                token,
                self.authentication_timeout,
                self.udp_socket_creator.clone(),
            ));
        }
    }
}
