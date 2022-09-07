//! A `ProxyStream` that bypasses or proxies data through proxy server automatically

use std::{
    io::{self, IoSlice},
    pin::Pin,
    sync::Arc,
    task::{self, Poll},
};

use cfg_if::cfg_if;

use pin_project::pin_project;
use shadowsocks::{
    context::SharedContext,
    create_connector_then,
    net::{ConnectOpts, FlowStat},
    relay::{socks5::Address, tcprelay::proxy_stream::ProxyClientStream},
    transport::{DeviceOrGuard, RateLimitedStream, StreamConnection},
};

#[cfg(feature = "rate-limit")]
use shadowsocks::transport::RateLimiter;

#[cfg(feature = "trojan")]
use shadowsocks::trojan;

#[cfg(feature = "vless")]
use shadowsocks::vless;

#[cfg(feature = "tuic")]
use shadowsocks::tuic;

use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::Notify,
};

use crate::{
    local::{context::ServiceContext, loadbalancing::ServerIdent},
    net::MonProxyStream,
};

cfg_if! {
    if #[cfg(feature = "local-fake-mode")] {
        use crate::local::context::FakeMode;
        use futures::Future;
        type CloseWaiter = Pin<Box<dyn Future<Output = ()> + Send + Sync>>;
    }
}

use super::auto_proxy_io::AutoProxyIo;

/// Unified stream for bypassed and proxied connections
#[allow(clippy::large_enum_variant)]
#[pin_project(project = AutoProxyClientStreamStreamProj)]
enum AutoProxyClientStreamStream {
    Proxied(#[pin] ProxyClientStream<Box<dyn StreamConnection>>),
    #[cfg(feature = "trojan")]
    ProxiedTrojan(#[pin] trojan::ClientStream<Box<dyn StreamConnection>>),
    #[cfg(feature = "vless")]
    ProxiedVless(#[pin] vless::ClientStream<Box<dyn StreamConnection>>),
    #[cfg(feature = "tuic")]
    ProxiedTuic(#[pin] Box<dyn StreamConnection>),
    Bypassed(#[pin] Box<dyn StreamConnection>),
}

#[pin_project(project = AutoProxyClientStreamProj)]
pub struct AutoProxyClientStream {
    #[pin]
    s: AutoProxyClientStreamStream,

    #[pin]
    c: Option<CloseWaiter>,
}

impl AutoProxyClientStream {
    /// Connect to target `addr` via shadowsocks' server configured by `svr_cfg`
    pub async fn connect(
        context: &Arc<ServiceContext>,
        server: &ServerIdent,
        addr: &Address,
    ) -> io::Result<AutoProxyClientStream> {
        #[cfg(feature = "local-fake-mode")]
        if context.fake_mode().is_bypass() {
            return AutoProxyClientStream::connect_bypassed(context, addr).await;
        }

        if context.check_target_bypassed(&addr).await {
            AutoProxyClientStream::connect_bypassed(context, addr).await
        } else {
            AutoProxyClientStream::connect_proxied(context, server, addr).await
        }
    }

    /// Connect directly to target `addr`
    pub async fn connect_bypassed(context: &ServiceContext, addr: &Address) -> io::Result<AutoProxyClientStream> {
        // Connect directly.
        let stream = shadowsocks::net::TcpStream::connect_remote_with_opts(
            context.context_ref(),
            addr,
            context.connect_opts_ref(),
        )
        .await?;

        Ok(AutoProxyClientStream {
            s: AutoProxyClientStreamStream::Bypassed(Box::new(stream)),
            #[cfg(feature = "local-fake-mode")]
            c: None,
        })
    }

    /// Connect via server to target `addr`
    pub async fn connect_proxied(
        context: &Arc<ServiceContext>,
        server: &ServerIdent,
        addr: &Address,
    ) -> io::Result<AutoProxyClientStream> {
        match Self::connect_proxied_no_score(
            context.context(),
            context.connect_opts_ref(),
            server,
            addr,
            Some(context.flow_stat()),
            Some(context.connection_close_notify()),
            #[cfg(feature = "rate-limit")]
            Some(context.rate_limiter()),
            #[cfg(feature = "local-fake-mode")]
            context.fake_mode(),
        )
        .await
        {
            Ok(s) => Ok(s),
            Err(err) => {
                server.tcp_score().report_failure().await;
                return Err(err);
            }
        }
    }

    pub async fn connect_proxied_no_score(
        context: SharedContext,
        connect_opts: &ConnectOpts,
        svr: &ServerIdent,
        addr: &Address,
        flow_stat: Option<Arc<FlowStat>>,
        connection_close_notify: Option<Arc<Notify>>,
        #[cfg(feature = "rate-limit")] rate_limit: Option<Arc<RateLimiter>>,
        #[cfg(feature = "local-fake-mode")] fake_mode: FakeMode,
    ) -> io::Result<AutoProxyClientStream> {
        let svr_cfg = svr.server_config();
        create_connector_then!(Some(context.clone()), svr_cfg.connector_transport(), |connector| {
            let connector = Arc::new(connector);
            match svr_cfg.protocol() {
                shadowsocks::config::ServerProtocol::SS(ss_cfg) => {
                    #[cfg(feature = "local-fake-mode")]
                    let mut _ss_cfg_buf = None;

                    #[allow(unused_mut)]
                    let mut effect_ss_cfg = ss_cfg;

                    #[cfg(feature = "local-fake-mode")]
                    if let Some(fake_cfg) = fake_mode.is_param_error_for_ss(ss_cfg) {
                        _ss_cfg_buf = Some(fake_cfg);
                        effect_ss_cfg = _ss_cfg_buf.as_ref().unwrap();
                    }

                    let stream = ProxyClientStream::connect_with_opts_map(
                        context,
                        connector.as_ref(),
                        svr_cfg,
                        effect_ss_cfg,
                        addr,
                        connect_opts,
                        |#[allow(unused_mut)] stream| {
                            #[cfg(feature = "rate-limit")]
                            let stream = RateLimitedStream::from_stream(stream, rate_limit);

                            if let Some(flow_stat) = flow_stat {
                                Box::new(MonProxyStream::from_stream(stream, flow_stat, None))
                                    as Box<dyn StreamConnection>
                            } else {
                                Box::new(stream) as Box<dyn StreamConnection>
                            }
                        },
                    )
                    .await?;
                    Ok(AutoProxyClientStream {
                        s: AutoProxyClientStreamStream::Proxied(stream),
                        c: Self::create_close_waiter(connection_close_notify),
                    })
                }
                #[cfg(feature = "trojan")]
                shadowsocks::config::ServerProtocol::Trojan(trojan_cfg) => {
                    #[cfg(feature = "local-fake-mode")]
                    let mut _trojan_cfg_buf = None;

                    #[allow(unused_mut)]
                    let mut effect_trojan_cfg = trojan_cfg;

                    #[cfg(feature = "local-fake-mode")]
                    if let Some(fake_cfg) = fake_mode.is_param_error_for_trojan(trojan_cfg) {
                        _trojan_cfg_buf = Some(fake_cfg);
                        effect_trojan_cfg = _trojan_cfg_buf.as_ref().unwrap();
                    }

                    let stream = trojan::ClientStream::connect_stream(
                        connector.as_ref(),
                        svr_cfg,
                        effect_trojan_cfg,
                        addr.clone(),
                        connect_opts,
                        |stream| {
                            #[cfg(feature = "rate-limit")]
                            let stream = RateLimitedStream::from_stream(stream, rate_limit);

                            if let Some(flow_stat) = flow_stat {
                                Box::new(MonProxyStream::from_stream(stream, flow_stat, None))
                                    as Box<dyn StreamConnection>
                            } else {
                                Box::new(stream) as Box<dyn StreamConnection>
                            }
                        },
                    )
                    .await?;
                    Ok(AutoProxyClientStream {
                        s: AutoProxyClientStreamStream::ProxiedTrojan(stream),
                        c: Self::create_close_waiter(connection_close_notify),
                    })
                }
                #[cfg(feature = "vless")]
                shadowsocks::config::ServerProtocol::Vless(vless_cfg) => {
                    #[cfg(feature = "local-fake-mode")]
                    let mut _vless_cfg_buf = None;

                    #[allow(unused_mut)]
                    let mut effect_vless_cfg = vless_cfg;

                    #[cfg(feature = "local-fake-mode")]
                    if let Some(fake_cfg) = fake_mode.is_param_error_for_vless(vless_cfg) {
                        _vless_cfg_buf = Some(fake_cfg);
                        effect_vless_cfg = _vless_cfg_buf.as_ref().unwrap();
                    }

                    let stream = vless::ClientStream::connect(
                        connector.as_ref(),
                        svr_cfg,
                        effect_vless_cfg,
                        vless::protocol::RequestCommand::TCP,
                        Some(addr.clone()),
                        connect_opts,
                        |stream| {
                            #[cfg(feature = "rate-limit")]
                            let stream = RateLimitedStream::from_stream(stream, rate_limit);

                            if let Some(flow_stat) = flow_stat {
                                Box::new(MonProxyStream::from_stream(stream, flow_stat, None))
                                    as Box<dyn StreamConnection>
                            } else {
                                Box::new(stream) as Box<dyn StreamConnection>
                            }
                        },
                    )
                    .await?;
                    Ok(AutoProxyClientStream {
                        s: AutoProxyClientStreamStream::ProxiedVless(stream),
                        c: Self::create_close_waiter(connection_close_notify),
                    })
                }
                #[cfg(feature = "tuic")]
                shadowsocks::config::ServerProtocol::Tuic(_tuic_cfg) => {
                    use shadowsocks::tuic;
                    use tuic::client::{Address as RelayAddress, Request as RelayRequest};

                    let target_addr = match addr {
                        Address::DomainNameAddress(domain, port) => {
                            RelayAddress::DomainAddress(domain.clone(), port.clone())
                        }
                        Address::SocketAddress(addr) => RelayAddress::SocketAddress(addr.clone()),
                    };

                    let (relay_req, relay_resp_rx) = RelayRequest::new_connect(target_addr);

                    svr.tuic_dispatcher().unwrap().send_req(relay_req).await?;

                    let stream = match relay_resp_rx.await {
                        Ok(stream) => stream,
                        Err(err) => {
                            return Err(io::Error::new(io::ErrorKind::Other, err));
                        }
                    };

                    #[cfg(feature = "rate-limit")]
                    let stream = RateLimitedStream::from_stream(stream, rate_limit);

                    let stream = if let Some(flow_stat) = flow_stat {
                        Box::new(MonProxyStream::from_stream(stream, flow_stat, None)) as Box<dyn StreamConnection>
                    } else {
                        Box::new(stream) as Box<dyn StreamConnection>
                    };

                    Ok(AutoProxyClientStream {
                        s: AutoProxyClientStreamStream::ProxiedTuic(stream),
                        c: Self::create_close_waiter(connection_close_notify),
                    })
                }
            }
        })
    }

    fn create_close_waiter(notify: Option<Arc<Notify>>) -> Option<CloseWaiter> {
        notify.map(|c| {
            let f = async move {
                c.notified().await;
            };

            Box::pin(f) as CloseWaiter
        })
    }

    #[cfg(feature = "local-fake-mode")]
    fn is_fake_closed(c: Pin<&mut Option<CloseWaiter>>, cx: &mut task::Context<'_>) -> io::Result<()> {
        let c = c.as_pin_mut();
        if let Some(c) = c {
            match c.poll(cx) {
                Poll::Ready(()) => {
                    return Err(io::Error::new(io::ErrorKind::Other, "fc"));
                }
                Poll::Pending => {}
            }
        }

        Ok(())
    }
}

impl AutoProxyIo for AutoProxyClientStream {
    fn is_proxied(&self) -> bool {
        match self.s {
            AutoProxyClientStreamStream::Bypassed(..) => false,
            _ => true,
        }
    }
}

impl AsyncRead for AutoProxyClientStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let AutoProxyClientStreamProj { s, c } = self.project();

        #[cfg(feature = "local-fake-mode")]
        if let Err(err) = Self::is_fake_closed(c, cx) {
            return Poll::Ready(Err(err));
        }

        match s.project() {
            AutoProxyClientStreamStreamProj::Proxied(s) => s.poll_read(cx, buf),
            #[cfg(feature = "trojan")]
            AutoProxyClientStreamStreamProj::ProxiedTrojan(s) => s.poll_read(cx, buf),
            #[cfg(feature = "vless")]
            AutoProxyClientStreamStreamProj::ProxiedVless(s) => s.poll_read(cx, buf),
            #[cfg(feature = "tuic")]
            AutoProxyClientStreamStreamProj::ProxiedTuic(s, ..) => s.poll_read(cx, buf),
            AutoProxyClientStreamStreamProj::Bypassed(s) => s.poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for AutoProxyClientStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let AutoProxyClientStreamProj {
            s,
            #[cfg(feature = "local-fake-mode")]
            c,
        } = self.project();

        #[cfg(feature = "local-fake-mode")]
        if let Err(err) = Self::is_fake_closed(c, cx) {
            return Poll::Ready(Err(err));
        }

        match s.project() {
            AutoProxyClientStreamStreamProj::Proxied(s) => s.poll_write(cx, buf),
            #[cfg(feature = "trojan")]
            AutoProxyClientStreamStreamProj::ProxiedTrojan(s) => s.poll_write(cx, buf),
            #[cfg(feature = "vless")]
            AutoProxyClientStreamStreamProj::ProxiedVless(s) => s.poll_write(cx, buf),
            #[cfg(feature = "tuic")]
            AutoProxyClientStreamStreamProj::ProxiedTuic(s, ..) => s.poll_write(cx, buf),
            AutoProxyClientStreamStreamProj::Bypassed(s) => s.poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        let AutoProxyClientStreamProj {
            s,
            #[cfg(feature = "local-fake-mode")]
            c,
        } = self.project();

        #[cfg(feature = "local-fake-mode")]
        if let Err(err) = Self::is_fake_closed(c, cx) {
            return Poll::Ready(Err(err));
        }

        match s.project() {
            AutoProxyClientStreamStreamProj::Proxied(s) => s.poll_flush(cx),
            #[cfg(feature = "trojan")]
            AutoProxyClientStreamStreamProj::ProxiedTrojan(s) => s.poll_flush(cx),
            #[cfg(feature = "vless")]
            AutoProxyClientStreamStreamProj::ProxiedVless(s) => s.poll_flush(cx),
            #[cfg(feature = "tuic")]
            AutoProxyClientStreamStreamProj::ProxiedTuic(s, ..) => s.poll_flush(cx),
            AutoProxyClientStreamStreamProj::Bypassed(s) => s.poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        let AutoProxyClientStreamProj {
            s,
            #[cfg(feature = "local-fake-mode")]
            c,
        } = self.project();

        #[cfg(feature = "local-fake-mode")]
        if let Err(err) = Self::is_fake_closed(c, cx) {
            return Poll::Ready(Err(err));
        }

        match s.project() {
            AutoProxyClientStreamStreamProj::Proxied(s) => s.poll_shutdown(cx),
            #[cfg(feature = "trojan")]
            AutoProxyClientStreamStreamProj::ProxiedTrojan(s) => s.poll_shutdown(cx),
            #[cfg(feature = "vless")]
            AutoProxyClientStreamStreamProj::ProxiedVless(s) => s.poll_shutdown(cx),
            #[cfg(feature = "tuic")]
            AutoProxyClientStreamStreamProj::ProxiedTuic(s, ..) => s.poll_shutdown(cx),
            AutoProxyClientStreamStreamProj::Bypassed(s) => s.poll_shutdown(cx),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let AutoProxyClientStreamProj {
            s,
            #[cfg(feature = "local-fake-mode")]
            c,
        } = self.project();

        #[cfg(feature = "local-fake-mode")]
        if let Err(err) = Self::is_fake_closed(c, cx) {
            return Poll::Ready(Err(err));
        }

        match s.project() {
            AutoProxyClientStreamStreamProj::Proxied(s) => s.poll_write_vectored(cx, bufs),
            #[cfg(feature = "trojan")]
            AutoProxyClientStreamStreamProj::ProxiedTrojan(s) => s.poll_write_vectored(cx, bufs),
            #[cfg(feature = "vless")]
            AutoProxyClientStreamStreamProj::ProxiedVless(s) => s.poll_write_vectored(cx, bufs),
            #[cfg(feature = "tuic")]
            AutoProxyClientStreamStreamProj::ProxiedTuic(s, ..) => s.poll_write_vectored(cx, bufs),
            AutoProxyClientStreamStreamProj::Bypassed(s) => s.poll_write_vectored(cx, bufs),
        }
    }
}

// impl From<ProxyClientStream<MonProxyStream<S>>> for AutoProxyClientStream {
//     fn from(s: ProxyClientStream<MonProxyStream<S>>) -> Self {
//         AutoProxyClientStream::Proxied(s)
//     }
// }

impl StreamConnection for AutoProxyClientStream {
    fn check_connected(&self) -> bool {
        match self.s {
            AutoProxyClientStreamStream::Proxied(ref s) => s.check_connected(),
            #[cfg(feature = "trojan")]
            AutoProxyClientStreamStream::ProxiedTrojan(ref s) => s.check_connected(),
            #[cfg(feature = "vless")]
            AutoProxyClientStreamStream::ProxiedVless(ref s) => s.check_connected(),
            #[cfg(feature = "tuic")]
            AutoProxyClientStreamStream::ProxiedTuic(ref s, ..) => s.check_connected(),
            AutoProxyClientStreamStream::Bypassed(ref s) => s.check_connected(),
        }
    }

    #[cfg(feature = "rate-limit")]
    fn set_rate_limit(&mut self, rate_limit: Option<Arc<shadowsocks::transport::RateLimiter>>) {
        match self.s {
            AutoProxyClientStreamStream::Proxied(ref mut s) => {
                s.set_rate_limit(rate_limit);
            }
            #[cfg(feature = "trojan")]
            AutoProxyClientStreamStream::ProxiedTrojan(ref mut s) => {
                s.set_rate_limit(rate_limit);
            }
            #[cfg(feature = "vless")]
            AutoProxyClientStreamStream::ProxiedVless(ref mut s) => {
                s.set_rate_limit(rate_limit);
            }
            #[cfg(feature = "tuic")]
            AutoProxyClientStreamStream::ProxiedTuic(ref mut s, ..) => {
                s.set_rate_limit(rate_limit);
            }
            AutoProxyClientStreamStream::Bypassed(ref _s) => {}
        }
    }

    fn physical_device(&self) -> DeviceOrGuard<'_> {
        match self.s {
            AutoProxyClientStreamStream::Proxied(ref s) => s.physical_device(),
            #[cfg(feature = "trojan")]
            AutoProxyClientStreamStream::ProxiedTrojan(ref s) => s.physical_device(),
            #[cfg(feature = "vless")]
            AutoProxyClientStreamStream::ProxiedVless(ref s) => s.physical_device(),
            #[cfg(feature = "tuic")]
            AutoProxyClientStreamStream::ProxiedTuic(ref s, ..) => s.physical_device(),
            AutoProxyClientStreamStream::Bypassed(ref s) => s.physical_device(),
        }
    }
}
