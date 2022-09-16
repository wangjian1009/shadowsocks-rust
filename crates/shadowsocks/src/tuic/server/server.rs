use quinn::{Endpoint, Incoming, ServerConfig};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::{collections::HashSet, io::Result, sync::Arc, time::Duration};

use crate::policy::ServerPolicy;

use super::{connection::Connection, UdpSocketCreator};

pub struct Server {
    incoming: Incoming,
    token: Arc<HashSet<[u8; 32]>>,
    authentication_timeout: Duration,
    udp_socket_creator: Arc<Box<dyn UdpSocketCreator>>,
    policy: Arc<Box<dyn ServerPolicy>>,
}

impl Server {
    pub fn init(
        config: ServerConfig,
        socket: std::net::UdpSocket,
        token: HashSet<[u8; 32]>,
        auth_timeout: Duration,
        udp_socket_creator: Arc<Box<dyn UdpSocketCreator>>,
        policy: Arc<Box<dyn ServerPolicy>>,
    ) -> Result<Self> {
        let (endpoint, incoming) = Endpoint::server(
            config,
            match socket.local_addr()? {
                SocketAddr::V4(_) => SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0),
                SocketAddr::V6(_) => SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0),
            },
        )?;
        endpoint.rebind(socket)?;

        Ok(Self {
            incoming,
            token: Arc::new(token),
            authentication_timeout: auth_timeout,
            udp_socket_creator,
            policy,
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
                self.policy.clone(),
            ));
        }
    }
}
