use cfg_if::cfg_if;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::{io::{self, AsyncReadExt, AsyncWriteExt}, time::{self, Duration, Instant}};
use tun::{AsyncDevice, Configuration as TunConfiguration, Error as TunError, Layer};

use shadowsocks::net::UdpSocket;
use shadowsocks::wg;

cfg_if! {
    if #[cfg(feature = "rate-limit")] {
        use nonzero_ext::*;
        use shadowsocks::transport::{NegativeMultiDecision};
    }
}

use crate::config::{LocalInstanceConfig, ProtocolType};

use super::{ServerHandle, ServiceContext};

const MAX_UDP_SIZE: usize = 1472; // (1 << 16) - 1;
const HANDSHAKE_RATE_LIMIT: u64 = 10;
const TICK_DURATION: Duration = Duration::from_millis(250);
const RATE_LIMITER_RESET_DURATION: Duration = Duration::from_secs(1);

enum ProcessError {
    UdpReconnect,
}

pub(super) async fn create_wg_server(
    context: ServiceContext,
    vfut: &mut Vec<ServerHandle>,
    local: Vec<LocalInstanceConfig>,
    wg_config: &wg::Config,
) -> io::Result<()> {
    // tracing::error!("xxxxx create_wg_server: {:?}", wg_config);

    if local.len() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "wireguard only support one interface",
        ));
    }

    let local_config = &local[0];

    if !matches!(local_config.config.protocol, ProtocolType::Tun) {
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
    let mut tun_device = read_tun_device(local_config).await?;

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
            tracing::error!(err = ?_err, "wg: create Tunn error");
            return Err(io::Error::new(io::ErrorKind::Other, "wireguard create Tunn error"));
        }
    };

    // 创建udp socket
    let udp_remote_addr = match peer_config.endpoint.as_ref() {
        Some(addr) => addr.clone(),
        None => {
            tracing::error!("wg: no target error");
            return Err(io::Error::new(io::ErrorKind::Other, "wireguard no target error"));
        }
    };

    let mut udp_socket = match UdpSocket::connect_with_opts(&udp_remote_addr, context.connect_opts_ref()).await {
        Ok(sock) => Some(sock),
        Err(err) => {
            tracing::error!(err = ?err, "wg: create udp socket error");
            None
        }
    };

    let mtu = wg_config.itf.mtu.unwrap_or(1420);
    if mtu > MAX_UDP_SIZE - 32 {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("wireguard mtu {} overflow, max-mtu={}", mtu, MAX_UDP_SIZE - 32)
        ));
    }
    
    vfut.push(ServerHandle(tokio::spawn(async move {
        #[cfg(feature = "local-fake-mode")]
        let mut fake_updated = false;

        let cancel_waiter = context.cancel_waiter();
        let rate_limit = context.rate_limiter();

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
                    
                    wireguard_tick(&tunnel, &mut udp_socket, &mut dst_buf[..]).await
                }
                r = tun_device.read(&mut tun_src_buf[..]) => {
                    let src = match r {
                        Ok(n) => &tun_src_buf[..n],
                        Err(err) => {
                            tracing::error!(err = ?err, "wg: tun read error");
                            return Err(err);
                        }
                    };
                    flow_state.incr_tx(src.len() as u64);
                    tun_processed += src.len();

                    wireguard_tun_input(&tunnel, &mut udp_socket, &mut dst_buf[..], src).await
                }
                r = udp_recv(&mut udp_socket, &mut udp_src_buf[..]) => {
                    match r {
                        Ok(src) => {
                            let r = wireguard_udp_input(&tunnel, &mut tun_device, &udp_socket, &udp_remote_addr, &mut dst_buf[..], src, &wg_rate_limiter).await;
                            match r {
                                Ok(tun_writed) => {
                                    flow_state.incr_rx(tun_writed as u64);
                                    tun_processed = tun_writed;
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
                    tracing::info!("wg: canceled");
                    return Ok(()); 
                }
            };

            if let Err(err) = r {
                match err {
                    ProcessError::UdpReconnect => {
                        match UdpSocket::connect_with_opts(&udp_remote_addr, context.connect_opts_ref()).await {
                            Ok(sock) => {
                                udp_socket = Some(sock);
                                tracing::info!("wg: tick: udp_sock recreated");
                            }
                            Err(err) => {
                                if err.kind() == io::ErrorKind::NotFound {
                                    tracing::error!(err = ?err, "wg: re create udp socket error, app exited");
                                    return Err(err);
                                }
                                else {
                                    tracing::error!(err = ?err, "wg: re create udp socket error");
                                }
                            }
                        };
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
                                    tracing::info!("wg: canceled");
                                    return Ok(()); 
                                }
                            }
                        },
                        NegativeMultiDecision::InsufficientCapacity => {
                            // 读入的数据超过了最大读取数据，在读取时已经保护过，不应该再进入这个情况
                            tracing::error!("wg: tun processed {}, rate-limit unexpected", tun_processed);
                        }
                    }
                }
            }
        }
    })));

    Ok(())
}

/// Return: need reconnect
#[inline]
async fn wireguard_tick(tunnel: &wg::Tunn, udp_socket: &mut Option<UdpSocket>, dst_buf: &mut [u8]) -> Result<(), ProcessError> {
    match tunnel.update_timers(&mut dst_buf[..]) {
        wg::TunnResult::Done => Ok(()),
        wg::TunnResult::Err(wg::WireGuardError::ConnectionExpired) => {
            tracing::info!("wg: tick: Connection Expired");
            Err(ProcessError::UdpReconnect)
        }
        wg::TunnResult::Err(e) => {
            tracing::error!(error = ?e, "wg: tick: update_timers error");
            Ok(())
        }
        wg::TunnResult::WriteToNetwork(packet) => udp_send(udp_socket, &packet).await,
        _ => {
            tracing::error!("wg: tick: Unexpected result from update_timers");
            Ok(())
        }
    }
}

#[inline]
async fn wireguard_tun_input(
    tunnel: &wg::Tunn,
    udp_socket: &Option<UdpSocket>,
    dst_buf: &mut [u8],
    src: &[u8],
) -> Result<(), ProcessError> {
    match tunnel.encapsulate(src, dst_buf) {
        wg::TunnResult::Done => Ok(()),
        wg::TunnResult::Err(e) => {
            tracing::error!(error = ?e, "wg: tun_input: Encapsulate error");
            Ok(())
        }
        wg::TunnResult::WriteToNetwork(packet) => udp_send(udp_socket, &packet).await,
        _ => {
            tracing::error!("wg: tun_input: Unexpected result from encapsulate");
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
            udp_send(udp_socket, cookie).await?;
            return Ok(0);
        }
        Err(err) => {
            tracing::trace!(err = ?err, "wg: udp_input: verify packet error");
            return Ok(0);
        }
    };

    let mut tun_write = 0;

    // We found a peer, use it to decapsulate the message+
    let mut flush = false; // Are there packets to send from the queue?
    match tunnel.handle_verified_packet(parsed_packet, dst_buf) {
        wg::TunnResult::Done => {}
        wg::TunnResult::Err(err) => {
            tracing::trace!(err = ?err, "wg: udp_input: handle packet error");
            return Ok(0);
        }
        wg::TunnResult::WriteToNetwork(packet) => {
            flush = true;
            udp_send(udp_socket, packet).await?;
        }
        wg::TunnResult::WriteToTunnelV4(packet, _addr) => match tun_device.write(packet).await {
            Err(err) => {
                tracing::error!(err = ?err, "wg: udp_input: tun write packet(v4) error");
            }
            Ok(n) => {
                tun_write += n;
            }
        },
        wg::TunnResult::WriteToTunnelV6(packet, _addr) => match tun_device.write(packet).await {
            Err(err) => {
                tracing::error!(err = ?err, "wg: udp_input: tun write packet(v6) error");
            }
            Ok(n) => {
                tun_write += n;
            }
        },
    };

    if flush {
        // Flush pending queue
        while let wg::TunnResult::WriteToNetwork(packet) = tunnel.decapsulate(None, &[], dst_buf) {
            udp_send(udp_socket, packet).await?;
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
            let dummy_private_key : wg::Secret = wg::KeyBytes::random_from_rng(OsRng).into();
            let dummy_public_key = wg::PublicKey::from(&dummy_private_key);

            match tunnel.set_static_private(
                dummy_private_key,
                dummy_public_key,
                None,
            ) {
                Ok(()) => {
                    tracing::info!("wg: fake update success");
                }
                Err(err) => {
                    tracing::error!(err = ?err, "wg: fake update error");
                }
            }
            true
        }
        _ => false,
    }
}

async fn read_tun_device(config: &LocalInstanceConfig) -> io::Result<AsyncDevice> {
    let mut tun_config = TunConfiguration::default();

    if let Some(addr) = config.config.tun_interface_address {
        tun_config.address(addr.addr()).netmask(addr.netmask());
    }
    if let Some(addr) = config.config.tun_interface_destination {
        tun_config.destination(addr.addr());
    }
    if let Some(name) = &config.config.tun_interface_name {
        tun_config.name(name);
    }

    #[cfg(unix)]
    if let Some(fd) = config.config.tun_device_fd {
        tun_config.raw_fd(fd);
    } else if let Some(ref fd_path) = config.config.tun_device_fd_from_path {
        use shadowsocks::net::UnixListener;
        use std::fs;

        let _ = fs::remove_file(fd_path);

        let listener = match UnixListener::bind(fd_path) {
            Ok(l) => l,
            Err(err) => {
                tracing::error!("failed to bind uds path \"{}\", error: {}", fd_path.display(), err);
                return Err(err);
            }
        };

        tracing::info!("waiting tun's file descriptor from {}", fd_path.display());

        loop {
            let (mut stream, peer_addr) = listener.accept().await?;

            let mut buffer = [0u8; 1024];
            let mut fd_buffer = [0];

            match stream.recv_with_fd(&mut buffer, &mut fd_buffer).await {
                Ok((n, fd_size)) => {
                    if fd_size == 0 {
                        tracing::error!(
                            "client {:?} didn't send file descriptors with buffer.size {} bytes",
                            peer_addr,
                            n
                        );
                        continue;
                    }

                    tracing::info!("got file descriptor {} for tun from {:?}", fd_buffer[0], peer_addr);

                    if let Err(err) = stream.write_u8(0).await {
                        tracing::error!(err = ?err, "client {:?} send recv fd success error", peer_addr);
                    }

                    tun_config.raw_fd(fd_buffer[0]);
                    break;
                }
                Err(err) => {
                    tracing::error!(
                        "failed to receive file descriptors from {:?}, error: {}",
                        peer_addr,
                        err
                    );
                }
            }
        }
    } else {
        tracing::error!("no tun fd setted");
        return Err(io::Error::new(io::ErrorKind::Other, "no tun fd setted"));
    }

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
async fn udp_recv<'a>(
    udp_socket: & Option<UdpSocket>,
    buf: &'a mut [u8],
) -> Result<&'a [u8], ProcessError> {
    match udp_socket.as_ref() {
        Some(udp_socket) => {
            match udp_socket.recv(buf).await {
                Ok(n) => Ok(&buf[..n]),
                Err(err) => {
                    tracing::error!(err = ?err, "wg: udp read error");
                    Err(ProcessError::UdpReconnect)
                }
            }
        }
        None => {
            time::sleep(Duration::from_secs(1)).await; // 等待一秒后触发重连
            Err(ProcessError::UdpReconnect)
        }
    }
}

#[inline]
async fn udp_send(
    udp_socket: &Option<UdpSocket>,
    packet: &[u8],
) -> Result<(), ProcessError> {
    if udp_socket.is_none() {
        return Err(ProcessError::UdpReconnect);
    }

    let udp_socket = udp_socket.as_ref().unwrap();
    match udp_socket.send(&packet).await {
        Err(err) => {
            tracing::error!(err = ?err, "wg: udp send error, len={}", packet.len());
            Err(ProcessError::UdpReconnect)
        }
        Ok(_) => {
            // if packet.len() > 1400 {
            //     tracing::info!("wg: udp send success, len={}", packet.len());
            // }
            Ok(())
        },
    }
}
