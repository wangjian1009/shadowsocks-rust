//! TCP Tunnel Server

use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use shadowsocks::{canceler::Canceler, net::TcpListener as ShadowTcpListener, relay::socks5::Address, ServerAddr};
use tokio::{net::TcpStream, time};
use tracing::{error, info, trace, Instrument};

use crate::local::{
    context::ServiceContext,
    loadbalancing::PingBalancer,
    net::{tcp::listener::create_standard_tcp_listener, AutoProxyClientStream},
    utils::{establish_tcp_tunnel, establish_tcp_tunnel_bypassed},
    StartStat,
};

pub struct TunnelTcpServerBuilder {
    context: Arc<ServiceContext>,
    client_config: ServerAddr,
    balancer: PingBalancer,
    forward_addr: Address,
    #[cfg(target_os = "macos")]
    launchd_socket_name: Option<String>,
}

impl TunnelTcpServerBuilder {
    pub(crate) fn new(
        context: Arc<ServiceContext>,
        client_config: ServerAddr,
        balancer: PingBalancer,
        forward_addr: Address,
    ) -> TunnelTcpServerBuilder {
        TunnelTcpServerBuilder {
            context,
            client_config,
            balancer,
            forward_addr,
            #[cfg(target_os = "macos")]
            launchd_socket_name: None,
        }
    }

    /// macOS launchd activate socket
    #[cfg(target_os = "macos")]
    pub fn set_launchd_socket_name(&mut self, n: String) {
        self.launchd_socket_name = Some(n);
    }

    pub async fn build(self) -> io::Result<TunnelTcpServer> {
        cfg_if::cfg_if! {
            if #[cfg(target_os = "macos")] {
                let listener = if let Some(launchd_socket_name) = self.launchd_socket_name {
                    use tokio::net::TcpListener as TokioTcpListener;
                    use crate::net::launch_activate_socket::get_launch_activate_tcp_listener;

                    let std_listener = get_launch_activate_tcp_listener(&launchd_socket_name, true)?;
                    let tokio_listener = TokioTcpListener::from_std(std_listener)?;
                    ShadowTcpListener::from_listener(tokio_listener, self.context.accept_opts())?
                } else {
                    create_standard_tcp_listener(&self.context, &self.client_config).await?
                };
            } else {
                let listener = create_standard_tcp_listener(&self.context, &self.client_config).await?;
            }
        }

        Ok(TunnelTcpServer {
            context: self.context,
            listener,
            balancer: self.balancer,
            forward_addr: self.forward_addr,
        })
    }
}

/// TCP Tunnel instance
pub struct TunnelTcpServer {
    context: Arc<ServiceContext>,
    listener: ShadowTcpListener,
    balancer: PingBalancer,
    forward_addr: Address,
}

impl TunnelTcpServer {
    /// Server's local address
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Start serving
    pub async fn run(self, start_stat: StartStat, canceler: Arc<Canceler>) -> io::Result<()> {
        info!("shadowsocks TCP tunnel listening on {}", self.listener.local_addr()?);
        start_stat.notify().await?;

        let forward_addr = Arc::new(self.forward_addr);
        let mut cancel_waiter = canceler.waiter();
        loop {
            let r = tokio::select! {
                r = self.listener.accept() => { r }
                _ = cancel_waiter.wait() => {
                    return Ok(());
                }
            };

            let (stream, peer_addr) = match r {
                Ok(s) => s,
                Err(err) => {
                    error!("accept failed with error: {}", err);
                    time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
            };

            tokio::spawn(handle_tcp_client(
                self.context.clone(),
                stream,
                self.balancer.clone(),
                peer_addr,
                forward_addr.clone(),
            ).in_current_span());
        }
    }
}

async fn handle_tcp_client(
    context: Arc<ServiceContext>,
    #[allow(unused_mut)] mut stream: TcpStream,
    balancer: PingBalancer,
    peer_addr: SocketAddr,
    forward_addr: Arc<Address>,
) -> io::Result<()> {
    let forward_addr: &Address = &forward_addr;

    if balancer.is_empty() {
        trace!("establishing tcp tunnel {} <-> {} direct", peer_addr, forward_addr);

        let mut remote = AutoProxyClientStream::connect_bypassed(context.as_ref(), &forward_addr).await?;
        return establish_tcp_tunnel_bypassed(&mut stream, &mut remote, peer_addr, &forward_addr, None).await;
    }

    let server = balancer.best_tcp_server();
    let svr_cfg = server.server_config();
    trace!(
        "establishing tcp tunnel {} <-> {} through sever {} (outbound: {})",
        peer_addr,
        forward_addr,
        svr_cfg.tcp_external_addr(),
        svr_cfg.addr(),
    );

    #[cfg(feature = "rate-limit")]
    let mut stream = shadowsocks::transport::RateLimitedStream::from_stream(stream, Some(context.rate_limiter()));

    let mut remote = AutoProxyClientStream::connect_proxied(&context, &server, &forward_addr).await?;
    establish_tcp_tunnel(
        context.as_ref(),
        svr_cfg,
        &mut stream,
        &mut remote,
        peer_addr,
        &forward_addr,
    )
    .await
}
