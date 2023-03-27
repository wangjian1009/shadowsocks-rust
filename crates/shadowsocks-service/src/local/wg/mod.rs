use std::os::unix::io::RawFd;
use tokio::io;

use shadowsocks::wg::{plt, set_configuration, Config as WgConfig, Configuration, WireGuard, WireGuardConfig};

use super::{ServerHandle, ServiceContext};

use crate::config::{LocalInstanceConfig, ProtocolType};

pub(super) async fn create_wg_server(
    context: ServiceContext,
    vfut: &mut Vec<ServerHandle>,
    local: Vec<LocalInstanceConfig>,
    wg_config: &WgConfig,
) -> io::Result<()> {
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

    let fd = read_tun_fd(local_config).await?;

    // create TUN device
    let (mut readers, writer) = plt::Tun::new_from_fd(fd).map_err(|e| {
        tracing::error!(err = ?e, "Failed to create TUN device");
        io::Error::new(io::ErrorKind::Other, "Failed to create TUN device")
    })?;

    // create WireGuard device
    let wg: WireGuard<plt::Tun, plt::UDP> = WireGuard::new(
        writer,
        context.connect_opts_ref().clone(),
        #[cfg(feature = "rate-limit")]
        context.rate_limiter(),
    );

    // add all Tun readers
    while let Some(reader) = readers.pop() {
        wg.add_tun_reader(reader);
    }

    let uapi_context = wg_config.uapi_configuration();
    tracing::trace!("uapi-config: {}", uapi_context);

    // wrap in configuration interface
    let mut cfg = WireGuardConfig::new(wg.clone());
    if let Err(err) = set_configuration(&mut cfg, uapi_context.as_str()) {
        tracing::error!(err = ?err, "Failed to create TUN device");
        return Err(io::Error::new(io::ErrorKind::Other, "Failed to configure device"));
    }

    let mtu = wg_config.itf.mtu.unwrap_or(1500);

    // block until all tun readers closed
    let _thread_wait = {
        let cfg = cfg.clone();
        std::thread::spawn(move || loop {
            tracing::info!("Tun up (mtu = {})", mtu);
            let _ = cfg.up(mtu); // TODO: handle

            wg.wait();
            tracing::error!("wg_wait: end");
        })
    };

    let flow_state = context.flow_stat();
    vfut.push(ServerHandle(tokio::spawn(async move {
        let mut last_tx = 0;
        let mut last_rx = 0;
        loop {
            let _ = tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            for peer in cfg.get_peers() {
                if peer.rx_bytes > last_rx {
                    flow_state.incr_rx(peer.rx_bytes - last_rx);
                    last_rx = peer.rx_bytes;
                }

                if peer.tx_bytes > last_tx {
                    flow_state.incr_tx(peer.tx_bytes - last_tx);
                    last_tx = peer.tx_bytes;
                }

                // tracing::error!("xxxxx: tx={}, rx={}", peer.rx_bytes, peer.tx_bytes);

                #[cfg(feature = "local-fake-mode")]
                {
                    use crate::local::context::FakeMode;

                    let fake_mode = context.fake_mode();
                    match fake_mode {
                        FakeMode::ParamError => {
                            cfg.remove_peer(&peer.public_key);
                            // tracing::error!("xxxxxxx: remove {:?}", peer.public_key);
                        }
                        _ => {}
                    }
                }
            }
        }
    })));

    Ok(())
}

async fn read_tun_fd(config: &LocalInstanceConfig) -> io::Result<RawFd> {
    if let Some(fd) = config.config.tun_device_fd {
        return Ok(fd);
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

                    return Ok(fd_buffer[0]);
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
}
