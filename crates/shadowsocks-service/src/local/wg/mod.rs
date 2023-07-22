use cfg_if::cfg_if;
use std::sync::Arc;
use std::{net::SocketAddr, os::fd::RawFd};
use tokio::{
    io::{self, AsyncReadExt},
    net::UdpSocket,
    time::{self, Duration, Instant},
};
use tun::{AsyncDevice, Configuration as TunConfiguration, Error as TunError, Layer};

use shadowsocks::net::{sys::create_outbound_udp_socket, AddrFamily};
use shadowsocks::wg;

cfg_if! {
    if #[cfg(feature = "rate-limit")] {
        use nonzero_ext::*;
        use shadowsocks::transport::{NegativeMultiDecision};
    }
}

use crate::{
    config::{LocalConfig, ProtocolType},
    local::StartStat,
};

use super::ServiceContext;

const MAX_UDP_SIZE: usize = 1472; // (1 << 16) - 1;
const HANDSHAKE_RATE_LIMIT: u64 = 10;
const TICK_DURATION: Duration = Duration::from_millis(250);
const RATE_LIMITER_RESET_DURATION: Duration = Duration::from_secs(1);

use super::tun_sys::{write_packet_with_pi, IFF_PI_PREFIX_LEN};

enum ProcessError {
    UdpReconnect,
}

pub struct Server {
    context: ServiceContext,
    tun_device: AsyncDevice,
    tunnel: Box<wg::Tunn>,
    mtu: usize,
    udp_remote_addr: SocketAddr,
    wg_rate_limiter: Arc<wg::RateLimiter>,
}

impl Server {
    pub async fn create(
        context: ServiceContext,
        fd: RawFd,
        local_config: &LocalConfig,
        wg_config: &wg::Config,
    ) -> io::Result<Self> {
        tracing::error!("xxxxx create_wg_server: {:?}", wg_config);

        if !matches!(local_config.protocol, ProtocolType::Tun) {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                "wireguard only support tun interface",
            ));
        }

        if wg_config.peers.len() != 1 {
            return Err(io::Error::new(io::ErrorKind::Other, "wireguard only support one peer"));
        }
        let peer_config = &wg_config.peers[0];

        let itf_private_key: wg::Secret = wg_config.itf.private_key.clone().into();
        let itf_public_key = wg::PublicKey::from(&itf_private_key);
        let peer_public_key: wg::PublicKey = peer_config.public_key.clone().into();

        // 读取设备
        let tun_device = read_tun_device(local_config, fd).await?;

        let wg_rate_limiter = Arc::new(wg::RateLimiter::new(&itf_public_key, HANDSHAKE_RATE_LIMIT));

        // 创建 tunnel
        let tunnel = match wg::Tunn::new(
            itf_private_key.clone(),
            peer_public_key.clone(),
            peer_config.pre_shared_key.as_ref().map(|e| e.clone().into()),
            peer_config.persistent_keep_alive.map(|e| e as u16),
            0,
            Some(wg_rate_limiter.clone()),
        ) {
            Ok(t) => t,
            Err(_err) => {
                tracing::error!(err = ?_err, "create Tunn error");
                return Err(io::Error::new(io::ErrorKind::Other, "wireguard create Tunn error"));
            }
        };

        // 创建udp socket
        let udp_remote_addr = match peer_config.endpoint.as_ref() {
            Some(addr) => addr.clone(),
            None => {
                tracing::error!("no target error");
                return Err(io::Error::new(io::ErrorKind::Other, "wireguard no target error"));
            }
        };

        let mtu = wg_config.itf.mtu.unwrap_or(1420);
        if mtu > MAX_UDP_SIZE - 32 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("wireguard mtu {} overflow, max-mtu={}", mtu, MAX_UDP_SIZE - 32),
            ));
        }

        Ok(Self {
            context,
            tun_device,
            tunnel,
            mtu,
            udp_remote_addr,
            wg_rate_limiter,
        })
    }

    pub async fn run(self, start_stat: StartStat) -> io::Result<()> {
        let Server {
            context,
            mut tun_device,
            tunnel,
            mtu,
            udp_remote_addr,
            wg_rate_limiter,
        } = self;

        let mut start_stat = Some(start_stat);

        #[cfg(feature = "local-fake-mode")]
        let mut fake_updated = false;

        let cancel_waiter = context.cancel_waiter();
        let rate_limit = context.rate_limiter();

        // Socket 重建
        let mut udp_socket_create_time = Instant::now();

        let af_family = match udp_remote_addr {
            SocketAddr::V4(..) => AddrFamily::Ipv4,
            SocketAddr::V6(..) => AddrFamily::Ipv6,
        };
        let mut udp_socket = match create_outbound_udp_socket(af_family, context.connect_opts_ref()).await {
            Ok(sock) => Some(sock),
            Err(err) => {
                tracing::error!(err = ?err, "create udp socket error");
                None
            }
        };

        // 流量统计
        let flow_state = context.flow_stat();

        // 读写缓存
        let mut dst_buf = vec![0; MAX_UDP_SIZE];
        let mut tun_src_buf = vec![0; mtu];
        let mut udp_src_buf = vec![0; MAX_UDP_SIZE];

        let mut next_tick = Instant::now();
        let mut next_rate_limiter_rest = Instant::now() + RATE_LIMITER_RESET_DURATION;
        loop {
            let mut tun_processed = 0;
            let r = tokio::select! {
                _ = time::sleep_until(next_tick) => {
                    next_tick = Instant::now() + TICK_DURATION; // tick 时间扣除处理实现

                    #[cfg(feature = "local-fake-mode")]
                    if !fake_updated {
                        fake_updated = sync_fake_mode(&context, &tunnel).await;
                    }

                    wireguard_tick(&tunnel, &mut udp_socket, &udp_remote_addr, &mut dst_buf[..]).await
                }
                r = tun_device.read(&mut tun_src_buf[..]) => {
                    let src = match r {
                        Ok(n) => {
                            if n <= IFF_PI_PREFIX_LEN {
                                tracing::error!("tun packet too short, packet: {:?}", &tun_src_buf[..n]);
                                continue;
                            }

                            &tun_src_buf[IFF_PI_PREFIX_LEN..n]
                        },
                        Err(err) => {
                            tracing::error!(err = ?err, "tun read error");
                            return Err(err);
                        }
                    };
                    // tracing::error!("tun recv, len={}", src.len());
                    flow_state.incr_tx(src.len() as u64);
                    tun_processed += src.len();

                    wireguard_tun_input(&tunnel, &mut udp_socket, &udp_remote_addr, &mut dst_buf[..], src).await
                }
                r = udp_recv(&mut udp_socket, &mut udp_src_buf[..]) => {
                    match r {
                        Ok(src) => {
                            let r = wireguard_udp_input(&tunnel, &mut tun_device, &udp_socket, &udp_remote_addr, &mut dst_buf[..], src, &wg_rate_limiter).await;
                            match r {
                                Ok(tun_writed) => {
                                    flow_state.incr_rx(tun_writed as u64);
                                    tun_processed = tun_writed;

                                    if start_stat.is_some() {
                                        let (duration, ..) = tunnel.stats();
                                        if duration.is_some() {
                                            tracing::info!("first handshake successed");
                                            start_stat.take().unwrap().notify().await;
                                        }
                                    }

                                    Ok(())
                                }
                                Err(err) => Err(err),
                            }
                        }
                        Err(err) => Err(err),
                    }
                }
                _ = time::sleep_until(next_rate_limiter_rest) => {
                    next_rate_limiter_rest = Instant::now() + RATE_LIMITER_RESET_DURATION;
                    wg_rate_limiter.reset_count();
                    Ok(())
                }
                _ = cancel_waiter.wait() => {
                    tracing::info!("canceled");
                    return Ok(());
                }
            };

            if let Err(err) = r {
                match err {
                    ProcessError::UdpReconnect => {
                        if udp_socket_create_time.elapsed() > Duration::from_secs(1) {
                            udp_socket_create_time = Instant::now();
                            match create_outbound_udp_socket(af_family, context.connect_opts_ref()).await {
                                Ok(sock) => {
                                    udp_socket = Some(sock);
                                    tracing::info!("tick: udp_sock recreated");
                                }
                                Err(err) => {
                                    if err.kind() == io::ErrorKind::NotFound {
                                        tracing::error!(err = ?err, "re create udp socket error, app exited");
                                        return Err(err);
                                    } else {
                                        tracing::error!(err = ?err, "re create udp socket error");
                                    }
                                }
                            };
                        }
                    }
                }
            }

            #[cfg(feature = "rate-limit")]
            if tun_processed > 0 {
                if let Err(err) = rate_limit.check_n((tun_processed as u32).into_nonzero().unwrap()) {
                    match err {
                        NegativeMultiDecision::BatchNonConforming(duration) => {
                            // tracing::error!("xxxxx: rate_limit: {:?}", duration);
                            tokio::select! {
                                _ = tokio::time::sleep(duration) => {}
                                _ = cancel_waiter.wait() => {
                                    tracing::info!("canceled");
                                    return Ok(());
                                }
                            }
                        }
                        NegativeMultiDecision::InsufficientCapacity => {
                            // 读入的数据超过了最大读取数据，在读取时已经保护过，不应该再进入这个情况
                            tracing::error!("tun processed {}, rate-limit unexpected", tun_processed);
                        }
                    }
                }
            }
        }
    }
}

/// Return: need reconnect
#[inline]
async fn wireguard_tick(
    tunnel: &wg::Tunn,
    udp_socket: &mut Option<UdpSocket>,
    udp_remote_addr: &SocketAddr,
    dst_buf: &mut [u8],
) -> Result<(), ProcessError> {
    match tunnel.update_timers(&mut dst_buf[..]) {
        wg::TunnResult::Done => Ok(()),
        wg::TunnResult::Err(wg::WireGuardError::ConnectionExpired) => {
            tracing::info!("tick: Connection Expired");
            Err(ProcessError::UdpReconnect)
        }
        wg::TunnResult::Err(e) => {
            tracing::error!(error = ?e, "tick: update_timers error");
            Ok(())
        }
        wg::TunnResult::WriteToNetwork(packet) => udp_send(udp_socket, udp_remote_addr, &packet).await,
        _ => {
            tracing::error!("tick: Unexpected result from update_timers");
            Ok(())
        }
    }
}

#[inline]
async fn wireguard_tun_input(
    tunnel: &wg::Tunn,
    udp_socket: &Option<UdpSocket>,
    udp_remote_addr: &SocketAddr,
    dst_buf: &mut [u8],
    src: &[u8],
) -> Result<(), ProcessError> {
    match tunnel.encapsulate(src, dst_buf) {
        wg::TunnResult::Done => Ok(()),
        wg::TunnResult::Err(e) => {
            tracing::error!(error = ?e, "tun_input: Encapsulate error");
            Ok(())
        }
        wg::TunnResult::WriteToNetwork(packet) => udp_send(udp_socket, udp_remote_addr, &packet).await,
        _ => {
            tracing::error!("tun_input: Unexpected result from encapsulate");
            Ok(())
        }
    }
}

#[inline]
async fn wireguard_udp_input(
    tunnel: &wg::Tunn,
    tun_device: &mut AsyncDevice,
    udp_socket: &Option<UdpSocket>,
    udp_remote_addr: &SocketAddr,
    dst_buf: &mut [u8],
    packet: &[u8],
    rate_limiter: &wg::RateLimiter,
) -> Result<usize, ProcessError> {
    // The rate limiter initially checks mac1 and mac2, and optionally asks to send a cookie
    let parsed_packet = match rate_limiter.verify_packet(Some(udp_remote_addr.ip()), packet, dst_buf) {
        Ok(packet) => packet,
        Err(wg::TunnResult::WriteToNetwork(cookie)) => {
            udp_send(udp_socket, udp_remote_addr, cookie).await?;
            return Ok(0);
        }
        Err(err) => {
            tracing::trace!(err = ?err, "udp_input: verify packet error");
            return Ok(0);
        }
    };

    let mut tun_write = 0;

    // We found a peer, use it to decapsulate the message+
    let mut flush = false; // Are there packets to send from the queue?
    match tunnel.handle_verified_packet(parsed_packet, dst_buf) {
        wg::TunnResult::Done => {}
        wg::TunnResult::Err(err) => {
            tracing::trace!(err = ?err, "udp_input: handle packet error");
            return Ok(0);
        }
        wg::TunnResult::WriteToNetwork(packet) => {
            flush = true;
            udp_send(udp_socket, udp_remote_addr, packet).await?;
        }
        wg::TunnResult::WriteToTunnelV4(packet, _addr) => match write_packet_with_pi(tun_device, packet).await {
            Err(err) => {
                tracing::error!(err = ?err, "udp_input: tun write packet(v4) error");
            }
            Ok(()) => {
                // tracing::error!("udp_input: tun write packet(v4) {}", packet.len());
                tun_write += packet.len();
            }
        },
        wg::TunnResult::WriteToTunnelV6(packet, _addr) => match write_packet_with_pi(tun_device, packet).await {
            Err(err) => {
                tracing::error!(err = ?err, "udp_input: tun write packet(v6) error");
            }
            Ok(()) => {
                // tracing::error!("udp_input: tun write packet(v6) {}", packet.len());
                tun_write += packet.len();
            }
        },
    };

    if flush {
        // Flush pending queue
        while let wg::TunnResult::WriteToNetwork(packet) = tunnel.decapsulate(None, &[], dst_buf) {
            udp_send(udp_socket, udp_remote_addr, packet).await?;
        }
    }

    Ok(tun_write)
}

#[cfg(feature = "local-fake-mode")]
#[inline]
async fn sync_fake_mode(context: &ServiceContext, tunnel: &wg::Tunn) -> bool {
    use crate::local::context::FakeMode;
    use rand::rngs::OsRng;

    let fake_mode = context.fake_mode();
    match fake_mode {
        FakeMode::ParamError => {
            let dummy_private_key: wg::Secret = wg::KeyBytes::random_from_rng(OsRng).into();
            let dummy_public_key = wg::PublicKey::from(&dummy_private_key);

            match tunnel.set_static_private(dummy_private_key, dummy_public_key, None) {
                Ok(()) => {
                    tracing::info!("fake update success");
                }
                Err(err) => {
                    tracing::error!(err = ?err, "fake update error");
                }
            }
            true
        }
        _ => false,
    }
}

async fn read_tun_device(config: &LocalConfig, fd: RawFd) -> io::Result<AsyncDevice> {
    let mut tun_config = TunConfiguration::default();

    if let Some(addr) = config.tun_interface_address {
        tun_config.address(addr.addr()).netmask(addr.netmask());
    }
    if let Some(addr) = config.tun_interface_destination {
        tun_config.destination(addr.addr());
    }
    if let Some(name) = &config.tun_interface_name {
        tun_config.name(name);
    }

    tun_config.raw_fd(fd);

    tun_config.layer(Layer::L3).up();

    #[cfg(any(target_os = "linux"))]
    tun_config.platform(|tun_config| {
        // IFF_NO_PI preventing excessive buffer reallocating
        tun_config.packet_information(false);
    });

    let device = match tun::create_as_async(&tun_config) {
        Ok(d) => d,
        Err(TunError::Io(err)) => return Err(err),
        Err(err) => return Err(io::Error::new(io::ErrorKind::Other, err)),
    };

    Ok(device)
}

#[inline]
async fn udp_recv<'a>(udp_socket: &Option<UdpSocket>, buf: &'a mut [u8]) -> Result<&'a [u8], ProcessError> {
    match udp_socket.as_ref() {
        Some(udp_socket) => match udp_socket.recv_from(buf).await {
            Ok((n, _addr)) => Ok(&buf[..n]),
            Err(err) => {
                tracing::error!(err = ?err, "udp read error");
                Err(ProcessError::UdpReconnect)
            }
        },
        None => {
            time::sleep(Duration::from_secs(1)).await; // 等待一秒后触发重连
            Err(ProcessError::UdpReconnect)
        }
    }
}

#[inline]
async fn udp_send(
    udp_socket: &Option<UdpSocket>,
    udp_remote_addr: &SocketAddr,
    packet: &[u8],
) -> Result<(), ProcessError> {
    if udp_socket.is_none() {
        return Err(ProcessError::UdpReconnect);
    }

    let udp_socket = udp_socket.as_ref().unwrap();
    match udp_socket.send_to(&packet, udp_remote_addr).await {
        Err(err) => {
            tracing::error!(err = ?err, "udp send error, len={}", packet.len());
            Err(ProcessError::UdpReconnect)
        }
        Ok(_) => {
            // if packet.len() > 1400 {
            //     tracing::error!("udp send success, len={}", packet.len());
            // }
            Ok(())
        }
    }
}
