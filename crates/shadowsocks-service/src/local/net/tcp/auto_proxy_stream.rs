//! A `ProxyStream` that bypasses or proxies data through proxy server automatically

use std::{
    io::{self, IoSlice},
    pin::Pin,
    sync::Arc,
    task::{self, Poll},
};

use pin_project::pin_project;
use shadowsocks::{
    config::ShadowsocksConfig,
    net::{Destination, TcpStream as BaseTcpStream},
    relay::{socks5::Address, tcprelay::proxy_stream::ProxyClientStream},
    transport::{Connector, StreamConnection},
};

#[cfg(feature = "trojan")]
use shadowsocks::trojan;

#[cfg(feature = "vless")]
use shadowsocks::vless;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::{
    local::{context::ServiceContext, loadbalancing::ServerIdent},
    net::MonProxyStream,
};

use super::auto_proxy_io::AutoProxyIo;

/// Unified stream for bypassed and proxied connections
#[pin_project(project = AutoProxyClientStreamProj)]
pub enum AutoProxyClientStream<S: StreamConnection> {
    Proxied(#[pin] ProxyClientStream<MonProxyStream<S>>),
    #[cfg(feature = "trojan")]
    ProxiedTrojan(#[pin] trojan::ClientStream<MonProxyStream<S>>),
    #[cfg(feature = "vless")]
    ProxiedVless(#[pin] vless::ClientStream<MonProxyStream<S>>),
    Bypassed(#[pin] BaseTcpStream),
}

/// Connect directly to target `addr`
pub async fn connect_bypassed(
    context: Arc<ServiceContext>,
    addr: Address,
) -> io::Result<AutoProxyClientStream<shadowsocks::net::TcpStream>> {
    // Connect directly.
    let stream =
        shadowsocks::net::TcpStream::connect_remote_with_opts(context.context_ref(), &addr, context.connect_opts_ref())
            .await?;

    Ok(AutoProxyClientStream::Bypassed(stream))
}

impl<S: StreamConnection> AutoProxyClientStream<S> {
    /// Connect to target `addr` via shadowsocks' server configured by `svr_cfg`
    pub async fn connect_proxied<C>(
        context: Arc<ServiceContext>,
        connector: Arc<C>,
        server: &ServerIdent,
        ss_cfg: &ShadowsocksConfig,
        addr: Address,
    ) -> io::Result<AutoProxyClientStream<S>>
    where
        C: Connector + Connector<TS = S>,
    {
        let flow_stat = context.flow_stat();
        let stream = match ProxyClientStream::connect_with_opts_map(
            context.context(),
            connector.as_ref(),
            server.server_config(),
            ss_cfg,
            addr,
            context.connect_opts_ref(),
            |#[allow(unused_mut)] mut stream| {
                #[cfg(feature = "rate-limit")]
                stream.set_rate_limit(context.rate_limiter());
                MonProxyStream::from_stream(stream, flow_stat, None)
            },
        )
        .await
        {
            Ok(s) => s,
            Err(err) => {
                server.tcp_score().report_failure().await;
                return Err(err);
            }
        };
        Ok(AutoProxyClientStream::Proxied(stream))
    }

    /// Connect to target `addr` via troan' server configured by `svr_cfg`
    #[cfg(feature = "trojan")]
    pub async fn connect_proxied_trojan<C>(
        context: Arc<ServiceContext>,
        connector: Arc<C>,
        server: &ServerIdent,
        trojan_cfg: &shadowsocks::config::TrojanConfig,
        addr: Address,
    ) -> io::Result<AutoProxyClientStream<S>>
    where
        C: Connector + Connector<TS = S>,
    {
        let flow_stat = context.flow_stat();
        let stream = match trojan::ClientStream::connect_stream(
            connector.as_ref(),
            server.server_config(),
            trojan_cfg,
            addr,
            context.connect_opts_ref(),
            |mut stream| {
                #[cfg(feature = "rate-limit")]
                stream.set_rate_limit(context.rate_limiter());
                MonProxyStream::from_stream(stream, flow_stat, None)
            },
        )
        .await
        {
            Ok(s) => s,
            Err(err) => {
                server.tcp_score().report_failure().await;
                return Err(err);
            }
        };
        Ok(AutoProxyClientStream::ProxiedTrojan(stream))
    }

    /// Connect to target `addr` via troan' server configured by `svr_cfg`
    #[cfg(feature = "vless")]
    pub async fn connect_proxied_vless<C>(
        context: Arc<ServiceContext>,
        connector: Arc<C>,
        server: &ServerIdent,
        vless_cfg: &shadowsocks::config::VlessConfig,
        addr: Address,
    ) -> io::Result<AutoProxyClientStream<S>>
    where
        C: Connector + Connector<TS = S>,
    {
        let flow_stat = context.flow_stat();
        let stream = match vless::ClientStream::connect_stream(
            connector.as_ref(),
            server.server_config(),
            vless_cfg,
            addr,
            context.connect_opts_ref(),
            |mut stream| {
                #[cfg(feature = "rate-limit")]
                stream.set_rate_limit(context.rate_limiter());
                MonProxyStream::from_stream(stream, flow_stat, None)
            },
        )
        .await
        {
            Ok(s) => s,
            Err(err) => {
                server.tcp_score().report_failure().await;
                return Err(err);
            }
        };
        Ok(AutoProxyClientStream::ProxiedVless(stream))
    }
}

impl<S: StreamConnection> AutoProxyIo for AutoProxyClientStream<S> {
    fn is_proxied(&self) -> bool {
        match *self {
            Self::Proxied(..) => true,
            #[cfg(feature = "trojan")]
            Self::ProxiedTrojan(..) => true,
            #[cfg(feature = "vless")]
            Self::ProxiedVless(..) => true,
            Self::Bypassed(..) => false,
        }
    }
}

impl<S: StreamConnection> AsyncRead for AutoProxyClientStream<S> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        match self.project() {
            AutoProxyClientStreamProj::Proxied(s) => s.poll_read(cx, buf),
            #[cfg(feature = "trojan")]
            AutoProxyClientStreamProj::ProxiedTrojan(s) => s.poll_read(cx, buf),
            #[cfg(feature = "vless")]
            AutoProxyClientStreamProj::ProxiedVless(s) => s.poll_read(cx, buf),
            AutoProxyClientStreamProj::Bypassed(s) => s.poll_read(cx, buf),
        }
    }
}

impl<S: StreamConnection> AsyncWrite for AutoProxyClientStream<S> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        match self.project() {
            AutoProxyClientStreamProj::Proxied(s) => s.poll_write(cx, buf),
            #[cfg(feature = "trojan")]
            AutoProxyClientStreamProj::ProxiedTrojan(s) => s.poll_write(cx, buf),
            #[cfg(feature = "vless")]
            AutoProxyClientStreamProj::ProxiedVless(s) => s.poll_write(cx, buf),
            AutoProxyClientStreamProj::Bypassed(s) => s.poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        match self.project() {
            AutoProxyClientStreamProj::Proxied(s) => s.poll_flush(cx),
            #[cfg(feature = "trojan")]
            AutoProxyClientStreamProj::ProxiedTrojan(s) => s.poll_flush(cx),
            #[cfg(feature = "vless")]
            AutoProxyClientStreamProj::ProxiedVless(s) => s.poll_flush(cx),
            AutoProxyClientStreamProj::Bypassed(s) => s.poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        match self.project() {
            AutoProxyClientStreamProj::Proxied(s) => s.poll_shutdown(cx),
            #[cfg(feature = "trojan")]
            AutoProxyClientStreamProj::ProxiedTrojan(s) => s.poll_shutdown(cx),
            #[cfg(feature = "vless")]
            AutoProxyClientStreamProj::ProxiedVless(s) => s.poll_shutdown(cx),
            AutoProxyClientStreamProj::Bypassed(s) => s.poll_shutdown(cx),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        match self.project() {
            AutoProxyClientStreamProj::Proxied(s) => s.poll_write_vectored(cx, bufs),
            #[cfg(feature = "trojan")]
            AutoProxyClientStreamProj::ProxiedTrojan(s) => s.poll_write_vectored(cx, bufs),
            #[cfg(feature = "vless")]
            AutoProxyClientStreamProj::ProxiedVless(s) => s.poll_write_vectored(cx, bufs),
            AutoProxyClientStreamProj::Bypassed(s) => s.poll_write_vectored(cx, bufs),
        }
    }
}

impl<S: StreamConnection> From<ProxyClientStream<MonProxyStream<S>>> for AutoProxyClientStream<S> {
    fn from(s: ProxyClientStream<MonProxyStream<S>>) -> Self {
        AutoProxyClientStream::Proxied(s)
    }
}

impl<S: StreamConnection> StreamConnection for AutoProxyClientStream<S> {
    fn local_addr(&self) -> io::Result<Destination> {
        match *self {
            AutoProxyClientStream::Proxied(ref s) => s.local_addr(),
            #[cfg(feature = "trojan")]
            AutoProxyClientStream::ProxiedTrojan(ref s) => s.local_addr(),
            #[cfg(feature = "vless")]
            AutoProxyClientStream::ProxiedVless(ref s) => s.local_addr(),
            AutoProxyClientStream::Bypassed(ref s) => <BaseTcpStream as StreamConnection>::local_addr(s),
        }
    }

    fn check_connected(&self) -> bool {
        match *self {
            AutoProxyClientStream::Proxied(ref s) => s.check_connected(),
            #[cfg(feature = "trojan")]
            AutoProxyClientStream::ProxiedTrojan(ref s) => s.check_connected(),
            #[cfg(feature = "vless")]
            AutoProxyClientStream::ProxiedVless(ref s) => s.check_connected(),
            AutoProxyClientStream::Bypassed(ref s) => s.check_connected(),
        }
    }

    #[cfg(feature = "rate-limit")]
    fn set_rate_limit(&mut self, rate_limit: Option<Arc<shadowsocks::transport::RateLimiter>>) {
        match self {
            AutoProxyClientStream::Proxied(ref mut s) => {
                s.set_rate_limit(rate_limit);
            }
            #[cfg(feature = "trojan")]
            AutoProxyClientStream::ProxiedTrojan(ref mut s) => {
                s.set_rate_limit(rate_limit);
            }
            #[cfg(feature = "vless")]
            AutoProxyClientStream::ProxiedVless(ref mut s) => {
                s.set_rate_limit(rate_limit);
            }
            AutoProxyClientStream::Bypassed(ref _s) => {}
        }
    }
}

#[macro_export]
macro_rules! connect_server_then {
    ($context:expr, $server:expr, $addr:expr, |$stream:ident| $body:block) => {{
        create_connector_then!(
            Some($context.context()),
            $server.server_config().connector_transport(),
            |connector| {
                let connector = Arc::new(connector);
                match $server.server_config().protocol() {
                    shadowsocks::config::ServerProtocol::SS(cfg) => {
                        let $stream =
                            AutoProxyClientStream::connect_proxied($context.clone(), connector, $server, cfg, $addr)
                                .await;
                        $body
                    }
                    #[cfg(feature = "trojan")]
                    shadowsocks::config::ServerProtocol::Trojan(cfg) => {
                        let $stream = AutoProxyClientStream::connect_proxied_trojan(
                            $context.clone(),
                            connector,
                            $server,
                            cfg,
                            $addr,
                        )
                        .await;
                        $body
                    }
                    #[cfg(feature = "vless")]
                    shadowsocks::config::ServerProtocol::Vless(cfg) => {
                        let $stream = AutoProxyClientStream::connect_proxied_vless(
                            $context.clone(),
                            connector,
                            $server,
                            cfg,
                            $addr,
                        )
                        .await;
                        $body
                    }
                }
            }
        )
    }};
}

#[macro_export]
macro_rules! auto_proxy_then {
    ($context:expr, $server:expr, $addr:expr, |$stream:ident| $body:block) => {{
        let _dup_addr = $addr.clone();
        if $context.check_target_bypassed(&_dup_addr).await {
            let $stream = crate::local::net::connect_bypassed($context.clone(), _dup_addr).await;
            $body
        } else {
            connect_server_then!($context, $server, _dup_addr, |$stream| { $body })
        }
    }};
}
