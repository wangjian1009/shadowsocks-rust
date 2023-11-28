//! TCP Tunnel Server

use std::{io, net::SocketAddr, sync::Arc, time::Duration};

use shadowsocks::{lookup_then, net::TcpListener as ShadowTcpListener, relay::socks5::Address, ServerAddr};
use tokio::{net::TcpStream, time};
use tracing::{error, info, trace};

use crate::local::{
    context::ServiceContext,
    loadbalancing::PingBalancer,
    net::AutoProxyClientStream,
    start_stat::StartStat,
    utils::{establish_tcp_tunnel, establish_tcp_tunnel_bypassed},
};

/// TCP Tunnel instance
pub struct TunnelTcpServer {
    context: Arc<ServiceContext>,
    listener: ShadowTcpListener,
    balancer: PingBalancer,
    forward_addr: Address,
}

impl TunnelTcpServer {
    pub(crate) async fn new(
        context: Arc<ServiceContext>,
        client_config: &ServerAddr,
        balancer: PingBalancer,
        forward_addr: Address,
    ) -> io::Result<TunnelTcpServer> {
        let listener = match *client_config {
            ServerAddr::SocketAddr(ref saddr) => {
                ShadowTcpListener::bind_with_opts(saddr, context.accept_opts()).await?
            }
            ServerAddr::DomainName(ref dname, port) => {
                lookup_then!(context.context_ref(), dname, port, |addr| {
                    ShadowTcpListener::bind_with_opts(&addr, context.accept_opts()).await
                })?
                .1
            }
        };

        Ok(TunnelTcpServer {
            context,
            listener,
            balancer,
            forward_addr,
        })
    }

    /// Server's local address
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Start serving
    pub async fn run(self, start_stat: StartStat) -> io::Result<()> {
        info!("shadowsocks TCP tunnel listening on {}", self.listener.local_addr()?);
        start_stat.notify().await?;

        let forward_addr = Arc::new(self.forward_addr);
        let cancel_waiter = self.context.cancel_waiter();
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
            ));
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
