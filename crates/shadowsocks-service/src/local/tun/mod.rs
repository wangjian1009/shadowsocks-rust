//! Shadowsocks Local server serving on a Tun interface

#[cfg(unix)]
use std::os::unix::io::RawFd;
use std::{
    io::{self, ErrorKind},
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use byte_string::ByteStr;
use ipnet::IpNet;
use shadowsocks::{canceler::Canceler, config::Mode};
use smoltcp::wire::{IpProtocol, TcpPacket, UdpPacket};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, error, info, trace, warn};

cfg_if::cfg_if! {
    if #[cfg(any(target_os = "ios",
                 target_os = "macos",
                 target_os = "linux",
                 target_os = "android",
                 target_os = "windows",
                 target_os = "freebsd"))] {
        use tun2::{
            create_as_async, AsyncDevice, Configuration as TunConfiguration, AbstractDevice, Error as TunError, Layer,
        };
    } else {
        use tun2::{AbstractDevice, Configuration as TunConfiguration, Error as TunError, Layer};

        mod fake_tun;
        use self::fake_tun::{create_as_async, AsyncDevice};
    }
}

use crate::local::{
    context::ServiceContext, loadbalancing::PingBalancer, net::UdpAssociationCloseReceiver, start_stat::StartStat,
};

#[cfg(feature = "local-dns")]
mod dns;

#[cfg(feature = "local-dns")]
pub use dns::DnsProcessor;

use self::{ip_packet::IpPacket, tcp::TcpTun, udp::UdpTun};

mod ip_packet;
mod tcp;
mod udp;
mod virt_device;

/// Tun service builder
pub struct TunBuilder {
    context: Arc<ServiceContext>,
    balancer: PingBalancer,
    tun_config: TunConfiguration,
    tun_effect_address_net: Option<IpNet>,
    udp_expiry_duration: Option<Duration>,
    udp_capacity: Option<usize>,
    mode: Mode,
}

/// TunConfiguration contains a HANDLE, which is a *mut c_void on Windows.
unsafe impl Send for TunBuilder {}

impl TunBuilder {
    /// Create a Tun service builder
    pub fn new(context: Arc<ServiceContext>, balancer: PingBalancer) -> TunBuilder {
        TunBuilder {
            context,
            balancer,
            tun_config: TunConfiguration::default(),
            tun_effect_address_net: None,
            udp_expiry_duration: None,
            udp_capacity: None,
            mode: Mode::TcpOnly,
        }
    }

    pub fn address(&mut self, addr: IpNet) {
        self.tun_config.address(addr.addr()).netmask(addr.netmask());
    }

    pub fn destination(&mut self, addr: IpNet) {
        self.tun_config.destination(addr.addr());
    }

    pub fn name(&mut self, name: &str) {
        self.tun_config.tun_name(name);
    }

    pub fn effect_address_net(&mut self, address_net: IpNet) {
        self.tun_effect_address_net = Some(address_net);
    }

    #[cfg(unix)]
    pub fn file_descriptor(&mut self, fd: RawFd) {
        self.tun_config.raw_fd(fd);
    }

    pub fn udp_expiry_duration(&mut self, udp_expiry_duration: Duration) {
        self.udp_expiry_duration = Some(udp_expiry_duration);
    }

    pub fn udp_capacity(&mut self, udp_capacity: usize) {
        self.udp_capacity = Some(udp_capacity);
    }

    pub fn mode(&mut self, mode: Mode) {
        self.mode = mode;
    }

    /// Build Tun server
    pub async fn build(mut self) -> io::Result<Tun> {
        self.tun_config.layer(Layer::L3).up();

        // XXX: tun2 set IFF_NO_PI by default.
        //
        // #[cfg(target_os = "linux")]
        // self.tun_config.platform_config(|tun_config| {
        //     // IFF_NO_PI preventing excessive buffer reallocating
        //     tun_config.packet_information(false);
        // });

        let device = match create_as_async(&self.tun_config) {
            Ok(d) => d,
            Err(TunError::Io(err)) => return Err(err),
            Err(err) => return Err(io::Error::new(ErrorKind::Other, err)),
        };

        let (udp, udp_close_rx) = UdpTun::new(
            self.context.clone(),
            self.balancer.clone(),
            self.udp_expiry_duration,
            self.udp_capacity,
        );

        let tcp = TcpTun::new(
            self.context.clone(),
            self.balancer,
            device.as_ref().mtu().unwrap_or(1500) as u32,
        );

        Ok(Tun {
            device,
            device_address_net: self.tun_effect_address_net,
            tcp,
            udp,
            udp_close_rx,
            mode: self.mode,
            #[cfg(feature = "local-dns")]
            dns_processor: None,
        })
    }
}

/// Tun service
pub struct Tun {
    device: AsyncDevice,
    device_address_net: Option<IpNet>,
    tcp: TcpTun,
    udp: UdpTun,
    udp_close_rx: UdpAssociationCloseReceiver,
    mode: Mode,

    #[cfg(feature = "local-dns")]
    dns_processor: Option<dns::DnsProcessor>,
}

impl Drop for Tun {
    fn drop(&mut self) {
        debug!("tun device dropped");
    }
}

impl Tun {
    #[cfg(feature = "local-dns")]
    pub fn set_dns_processor(&mut self, dns_processor: Option<DnsProcessor>) {
        self.dns_processor = dns_processor;
    }

    /// Start serving
    pub async fn run(mut self, start_stat: StartStat, canceler: Arc<Canceler>) -> io::Result<()> {
        info!(
            "shadowsocks tun device {}, mode {}",
            self.device
                .as_ref()
                .tun_name()
                .or_else(|r| Ok::<_, ()>(r.to_string()))
                .unwrap(),
            self.mode,
        );
        start_stat.notify().await?;

        let address_net = if let Some(address_net) = self.device_address_net {
            address_net
        } else {
            let address = match self.device.as_ref().address() {
                Ok(a) => a,
                Err(err) => {
                    error!("[TUN] failed to get device address, error: {}", err);
                    return Err(io::Error::new(io::ErrorKind::Other, err));
                }
            };

            let netmask = match self.device.as_ref().netmask() {
                Ok(n) => n,
                Err(err) => {
                    error!("[TUN] failed to get device netmask, error: {}", err);
                    return Err(io::Error::new(io::ErrorKind::Other, err));
                }
            };

            let address_net = match IpNet::with_netmask(address, netmask) {
                Ok(n) => n,
                Err(err) => {
                    error!("[TUN] invalid address {}, netmask {}, error: {}", address, netmask, err);
                    return Err(io::Error::new(io::ErrorKind::Other, err));
                }
            };

            trace!(
                "[TUN] tun device network: {} (address: {}, netmask: {})",
                address_net,
                address,
                netmask
            );

            address_net
        };

        let address_broadcast = address_net.broadcast();

        let mut packet_buffer = vec![0u8; 65536].into_boxed_slice();
        let mut cancel_waiter = canceler.waiter();

        loop {
            tokio::select! {
                _ = cancel_waiter.wait() => {
                    info!("[TUN] tun device canceled");
                    return Ok(());
                }

                // tun device
                n = self.device.read(&mut packet_buffer) => {
                    let n = n?;

                    let packet = &mut packet_buffer[..n];
                    trace!("[TUN] received IP packet {:?}", ByteStr::new(packet));

                    tokio::select! {
                        // handle IP packet
                        r = self.handle_tun_frame(&canceler, &address_broadcast, packet) => {
                            if let Err(err) = r {
                                error!("[TUN] handle IP frame failed, error: {}", err);
                            }
                        }
                        _ = cancel_waiter.wait() => {
                            info!("[TUN] tun device canceled (handle tun frame)");
                            return Ok(());
                        }
                    }
                }

                // UDP channel sent back
                packet = self.udp.recv_packet() => {
                    tokio::select! {
                        r = self.device.write(&packet) => {
                            match r {
                                Ok(n) => {
                                    if n < packet.len() {
                                        warn!("[TUN] sent IP packet (UDP), but truncated. sent {} < {}, {:?}", n, packet.len(), ByteStr::new(&packet));
                                    } else {
                                        trace!("[TUN] sent IP packet (UDP) {:?}", ByteStr::new(&packet));
                                    }
                                }
                                Err(err) => {
                                    error!("[TUN] failed to set packet information, error: {}, {:?}", err, ByteStr::new(&packet));
                                }
                            }
                        }
                        _ = cancel_waiter.wait() => {
                            info!("[TUN] tun device canceled (write udp packet)");
                            return Ok(());
                        }
                    }
                }

                // UDP keep-alive associations
                close_opt = self.udp_close_rx.recv() => {
                    let (peer_addr, reason) = match close_opt {
                        Some(v) => v,
                        None => {
                            error!("[TUN] udp close rx closed");
                            return Err(io::Error::new(io::ErrorKind::Other, "udp close rx closed"));
                        }
                    };

                    self.udp.close_association(&peer_addr, reason)
                }

                // TCP channel sent back
                packet = self.tcp.recv_packet() => {
                    tokio::select! {
                        r = self.device.write(&packet) => {
                            match r {
                                Ok(n) => {
                                    if n < packet.len() {
                                        warn!("[TUN] sent IP packet (TCP), but truncated. sent {} < {}, {:?}", n, packet.len(), ByteStr::new(&packet));
                                    } else {
                                        trace!("[TUN] sent IP packet (TCP) {:?}", ByteStr::new(&packet));
                                    }
                                }
                                Err(err) => {
                                    error!("[TUN] failed to set packet information, error: {}, {:?}", err, ByteStr::new(&packet));
                                }
                            }
                        }
                        _ = cancel_waiter.wait() => {
                            info!("[TUN] tun device canceled (write tcp packet)");
                            return Ok(());
                        }
                    }
                }
            }
        }
    }

    async fn handle_tun_frame(&mut self, canceler: &Arc<Canceler>, device_broadcast_addr: &IpAddr, frame: &[u8]) -> smoltcp::wire::Result<()> {
        let packet = match IpPacket::new_checked(frame)? {
            Some(packet) => packet,
            None => {
                warn!("unrecognized IP packet {:?}", ByteStr::new(frame));
                return Ok(());
            }
        };

        trace!("[TUN] {:?}", packet);

        let src_ip_addr = packet.src_addr();
        let dst_ip_addr = packet.dst_addr();
        let src_non_unicast = src_ip_addr == *device_broadcast_addr
            || match src_ip_addr {
                IpAddr::V4(v4) => v4.is_broadcast() || v4.is_multicast() || v4.is_unspecified(),
                IpAddr::V6(v6) => v6.is_multicast() || v6.is_unspecified(),
            };
        let dst_non_unicast = dst_ip_addr == *device_broadcast_addr
            || match dst_ip_addr {
                IpAddr::V4(v4) => v4.is_broadcast() || v4.is_multicast() || v4.is_unspecified(),
                IpAddr::V6(v6) => v6.is_multicast() || v6.is_unspecified(),
            };

        if src_non_unicast || dst_non_unicast {
            trace!(
                "[TUN] IP packet {} (unicast? {}) -> {} (unicast? {}) throwing away",
                src_ip_addr,
                !src_non_unicast,
                dst_ip_addr,
                !dst_non_unicast
            );
            return Ok(());
        }

        match packet.protocol() {
            IpProtocol::Tcp => {
                if !self.mode.enable_tcp() {
                    trace!("received TCP packet but mode is {}, throwing away", self.mode);
                    return Ok(());
                }

                let tcp_packet = match TcpPacket::new_checked(packet.payload()) {
                    Ok(p) => p,
                    Err(err) => {
                        error!(
                            "invalid TCP packet err: {}, src_ip: {}, dst_ip: {}, payload: {:?}",
                            err,
                            packet.src_addr(),
                            packet.dst_addr(),
                            ByteStr::new(packet.payload())
                        );
                        return Ok(());
                    }
                };

                let src_port = tcp_packet.src_port();
                let dst_port = tcp_packet.dst_port();

                let src_addr = SocketAddr::new(packet.src_addr(), src_port);
                let dst_addr = SocketAddr::new(packet.dst_addr(), dst_port);

                trace!(
                    "[TUN] TCP packet {} (unicast? {}) -> {} (unicast? {}) {}",
                    src_addr,
                    !src_non_unicast,
                    dst_addr,
                    !dst_non_unicast,
                    tcp_packet
                );

                // TCP first handshake packet.
                if let Err(err) = self.tcp.handle_packet(canceler, src_addr, dst_addr, &tcp_packet).await {
                    error!(
                        "handle TCP packet failed, error: {}, {} <-> {}, packet: {:?}",
                        err, src_addr, dst_addr, tcp_packet
                    );
                }

                self.tcp.drive_interface_state(frame).await;
            }
            IpProtocol::Udp => {
                if !self.mode.enable_udp() {
                    trace!("received UDP packet but mode is {}, throwing away", self.mode);
                    return Ok(());
                }

                let udp_packet = match UdpPacket::new_checked(packet.payload()) {
                    Ok(p) => p,
                    Err(err) => {
                        error!(
                            "invalid UDP packet err: {}, src_ip: {}, dst_ip: {}, payload: {:?}",
                            err,
                            packet.src_addr(),
                            packet.dst_addr(),
                            ByteStr::new(packet.payload())
                        );
                        return Ok(());
                    }
                };

                let src_port = udp_packet.src_port();
                let dst_port = udp_packet.dst_port();

                let src_addr = SocketAddr::new(src_ip_addr, src_port);
                let dst_addr = SocketAddr::new(packet.dst_addr(), dst_port);

                let payload = udp_packet.payload();
                trace!(
                    "[TUN] UDP packet {} (unicast? {}) -> {} (unicast? {}) {}",
                    src_addr,
                    !src_non_unicast,
                    dst_addr,
                    !dst_non_unicast,
                    udp_packet
                );

                #[cfg(feature = "local-dns")]
                if let Some(dns_processor) = self.dns_processor.as_ref() {
                    if &dst_addr == dns_processor.mock_dns_addr() {
                        return dns_processor
                            .handle_udp_frame(
                                src_addr,
                                dst_addr,
                                payload,
                                self.udp.manager().respond_writer(),
                                canceler,
                            )
                            .await;
                    }
                }

                if let Err(err) = self.udp.handle_packet(src_addr, dst_addr, payload, canceler).await {
                    error!("handle UDP packet failed, err: {}, packet: {:?}", err, udp_packet);
                }
            }
            IpProtocol::Icmp | IpProtocol::Icmpv6 => {
                // ICMP is handled by TCP's Interface.
                // smoltcp's interface will always send replies to EchoRequest
                self.tcp.drive_interface_state(frame).await;
            }
            _ => {
                debug!("IP packet ignored (protocol: {:?})", packet.protocol());
                return Ok(());
            }
        }

        Ok(())
    }
}
