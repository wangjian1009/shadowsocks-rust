//! Shadowsocks Local Utilities

use std::{io, net::SocketAddr, time::Duration};

use shadowsocks::{
    config::{ServerConfig, ServerProtocol},
    relay::{
        socks5::Address,
        tcprelay::{utils::copy_encrypted_bidirectional, utils_copy::copy_bidirectional},
    },
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    time,
};
use tracing::{debug, error, trace};

use cfg_if::cfg_if;

use crate::local::{context::ServiceContext, net::AutoProxyIo};

cfg_if! {
    if #[cfg(feature = "sniffer")] {
        use crate::sniffer;
        use crate::local::context::ProtocolAction;
    }
}

pub(crate) async fn establish_tcp_tunnel<P, S>(
    #[allow(unused)] context: &ServiceContext,
    svr_cfg: &ServerConfig,
    #[allow(unused_mut)] mut plain: P,
    shadow: &mut S,
    peer_addr: SocketAddr,
    target_addr: &Address,
) -> io::Result<()>
where
    P: AsyncRead + AsyncWrite + Unpin,
    S: AsyncRead + AsyncWrite + AutoProxyIo + Unpin,
{
    if shadow.is_proxied() {
    } else {
        return establish_tcp_tunnel_bypassed(&mut plain, shadow, peer_addr, target_addr, None).await;
    }

    #[cfg(feature = "sniffer")]
    let sniffer = sniffer::SnifferChainHead::new();

    #[cfg(feature = "sniffer-bittorrent")]
    let sniffer = sniffer.join(sniffer::SnifferBittorrent::new());

    #[cfg(feature = "sniffer-tls")]
    let sniffer = sniffer.join(sniffer::SnifferTls::new());

    #[cfg(feature = "sniffer")]
    let mut plain = sniffer::SnifferStream::from_stream(plain, sniffer);

    // https://github.com/shadowsocks/shadowsocks-rust/issues/232
    //
    // Protocols like FTP, clients will wait for servers to send Welcome Message without sending anything.
    //
    // Wait at most 500ms, and then sends handshake packet to remote servers.
    {
        let mut buffer = [0u8; 8192];
        match time::timeout(Duration::from_millis(500), plain.read(&mut buffer)).await {
            Ok(Ok(0)) => {
                // EOF. Just terminate right here.
                return Ok(());
            }
            Ok(Ok(n)) => {
                cfg_if! {
                    if #[cfg(feature = "sniffer")] {
                        if let Some(ProtocolAction::Reject) = context.protocol_action(plain.protocol()) {
                            error!(
                                "reject for protocol {:?} len={}",
                                plain.protocol().as_ref().unwrap(),
                                n,
                            );
                            return Ok(());
                        }

                        // tracing::error!(
                        //     "tcp check pass: xxxxxx: {} -> {} : {:?}: len={}, {:?}",
                        //     peer_addr,
                        //     target_addr,
                        //     plain.protocol(),
                        //     n,
                        //     &buffer[..std::cmp::min(n, 20)]
                        // );
                    }
                }
                // Send the first packet.
                shadow.write_all(&buffer[..n]).await?;
            }
            Ok(Err(err)) => return Err(err),
            Err(..) => {
                // Timeout. Send handshake to server.
                let _ = shadow.write(&[]).await?;

                trace!("sent handshake without data");
            }
        }
    }

    let (wn, rn, r) = match svr_cfg.protocol() {
        ServerProtocol::SS(ss_cfg) => copy_encrypted_bidirectional(ss_cfg.method(), shadow, &mut plain, None).await,
        #[cfg(feature = "trojan")]
        ServerProtocol::Trojan(_cfg) => copy_bidirectional(shadow, &mut plain, None).await,
        #[cfg(feature = "vless")]
        ServerProtocol::Vless(_cfg) => copy_bidirectional(shadow, &mut plain, None).await,
        #[cfg(feature = "tuic")]
        ServerProtocol::Tuic(_cfg) => copy_bidirectional(shadow, &mut plain, None).await,
    };
    match r {
        Ok(()) => {
            trace!(
                "tcp tunnel {} <-> {} (proxied) closed, L2R {} bytes, R2L {} bytes",
                peer_addr,
                target_addr,
                rn,
                wn
            );
        }
        Err(err) => {
            trace!(
                "tcp tunnel {} <-> {} (proxied) closed with error: {}",
                peer_addr,
                target_addr,
                err
            );
        }
    }

    Ok(())
}

pub(crate) async fn establish_tcp_tunnel_bypassed<P, S>(
    plain: &mut P,
    shadow: &mut S,
    peer_addr: SocketAddr,
    target_addr: &Address,
    idle_timeout: Option<Duration>,
) -> io::Result<()>
where
    P: AsyncRead + AsyncWrite + Unpin,
    S: AsyncRead + AsyncWrite + Unpin,
{
    debug!("established tcp tunnel {} <-> {} bypassed", peer_addr, target_addr);

    let (rn, wn, r) = copy_bidirectional(plain, shadow, idle_timeout).await;
    match r {
        Ok(()) => {
            trace!(
                "tcp tunnel {} <-> {} (bypassed) closed, L2R {} bytes, R2L {} bytes",
                peer_addr,
                target_addr,
                rn,
                wn
            );
        }
        Err(err) => {
            trace!(
                "tcp tunnel {} <-> {} (bypassed) closed with error: {}",
                peer_addr,
                target_addr,
                err
            );
        }
    }

    Ok(())
}
