use super::*;

use bytes::Bytes;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tracing::{debug, trace, warn};

use crate::{
    policy::{PacketAction, UdpSocket},
    relay::udprelay::MAXIMUM_UDP_PAYLOAD_SIZE,
    timeout::{TimeoutTicker, TimeoutWaiter},
    transport::{PacketMutWrite, PacketRead, StreamConnection},
};

use super::super::new_trojan_packet_connection;

pub type PacketSender = Sender<(Bytes, ServerAddr)>;
pub type PacketReceiver = Receiver<(Bytes, ServerAddr)>;

pub(super) async fn serve_udp(
    cancel_waiter: &CancelWaiter,
    incoming: impl StreamConnection + 'static,
    peer_addr: Option<ServerAddr>,
    idle_timeout: Duration,
    server_policy: Arc<Box<dyn ServerPolicy>>,
) -> CloseReason {
    let (mut incoming_reader, mut incoming_writer) = new_trojan_packet_connection(incoming);
    let (outgoing_pkt_tx, outgoing_pkt_rx) = channel(1);
    let (incoming_pkt_tx, mut incoming_pkt_rx) = channel(1);
    let (close_reason_tx, mut close_reason_rx) = channel(1);

    let timeout_waiter = TimeoutWaiter::new(idle_timeout);
    let flow_state = server_policy.create_connection_flow_state();

    // 启动处上游数据的任务
    let outgoing_task = {
        let timeout_ticker = timeout_waiter.ticker();

        let outgoing_socket = match server_policy.create_out_udp_socket().await {
            Ok(s) => Arc::new(s),
            Err(err) => {
                error!(error = ?err, "create outgoing socket error");
                return CloseReason::InternalError;
            }
        };

        let close_reason_tx = close_reason_tx.clone();
        tokio::spawn(
            async move {
                let outgoing_socket_1 = outgoing_socket.clone();
                let outgoing_socket_2 = outgoing_socket;
                let r = tokio::select!(
                    r = dispatch_outgoing_packet(outgoing_socket_1, outgoing_pkt_rx, timeout_ticker.clone()) => { r }
                    r = listen_outgoing_packet(outgoing_socket_2, incoming_pkt_tx, timeout_ticker.clone()) => { r }
                );

                if let Some(reason) = r {
                    if let Err(err) = close_reason_tx.send(reason).await {
                        trace!(error = err.to_string(), "close_reason_tx closed");
                    }
                }
            }
            .in_current_span(),
        )
    };

    tokio::pin!(timeout_waiter);

    let mut client_validated = false;

    let mut buffer = [0u8; MAXIMUM_UDP_PAYLOAD_SIZE];
    let mut incoming_pkt = None; // 需要发送回去的数据

    let close_reason = loop {
        tokio::select! {
            // 收取客户端请求
            r = incoming_reader.read_from(&mut buffer) => {
                let (n, addr) = match r {
                    Ok(r) => r,
                    Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => {
                        debug!("incoming closed");
                        break CloseReason::SockClosed;
                    }
                    Err(err) => {
                        error!(error = ?err, "incoming recv error");
                        break CloseReason::SockError;
                    }
                };

                timeout_waiter.tick();
                let data = Bytes::copy_from_slice(&buffer[..n]);
                flow_state.as_ref().map(|o| o.incr_rx(data.len() as u64));

                let check_peer_addr = if client_validated {
                    None
                }
                else {
                    client_validated = true;
                    peer_addr.clone()
                };

                let outgoing_pkt_tx = outgoing_pkt_tx.clone();
                let close_reason_tx = close_reason_tx.clone();
                let server_policy = server_policy.clone();
                tokio::spawn(async move {
                    let r = match server_policy.packet_check(check_peer_addr.as_ref(), &addr).await {
                        Err(err) => {
                            warn!(target = addr.to_string(), error = ?err, "packet check fail");
                            Some(CloseReason::ClientBlocked)
                        }
                        Ok(PacketAction::ClientBlocked) => {
                            warn!(target = addr.to_string(), "client blocked by ACL rules");
                            Some(CloseReason::ClientBlocked)
                        }
                        Ok(PacketAction::OutboundBlocked) => {
                            warn!(target = addr.to_string(), "outbound blocked by ACL rules");
                            Some(CloseReason::OutboundBlocked)
                        }
                        Ok(PacketAction::Remote) => {
                            let addr_for_log = addr.to_string();
                            match outgoing_pkt_tx.send((data, addr)).await {
                                Ok(()) => None,
                                Err(err) => {
                                    debug!(target = addr_for_log, error = ?err, "send channel closed");
                                    None
                                }
                            }
                        }
                    };

                    if let Some(r) = r {
                        if let Err(err) = close_reason_tx.send(r).await {
                            trace!(error = ?err, "send close reason error");
                        }
                    }
                }.in_current_span());
            }
            // 接收一个发回数据
            r = incoming_pkt_rx.recv(), if incoming_pkt.is_none() => {
                match r {
                    Some(r) => {
                        incoming_pkt = Some(r);
                    }
                    None => {
                        error!("incoming_pkt_rx broken");
                        break CloseReason::InternalError;
                    }
                };
            }
            // 发送一个收到的数据
            r = send_packet_to_incoming(&mut incoming_writer, &incoming_pkt), if incoming_pkt.is_some() => {
                match r {
                    Ok(()) => {
                        flow_state.as_ref().map(|o| o.incr_rx(incoming_pkt.unwrap().0.len() as u64));
                        incoming_pkt = None;
                    }
                    Err(err) => {
                        error!(error = ?err, "incoming send error");
                        break CloseReason::SockError;
                    }
                }
            }
            r = close_reason_rx.recv() => {
                break match r {
                    Some(r) => r,
                    None => {
                        error!("close_reason_rx broken");
                        CloseReason::InternalError
                    }
                }
            }
            // 等待超时
            _ = &mut timeout_waiter => {
                debug!(idle_timeout = idle_timeout.as_secs(), "timeout");
                break CloseReason::IdleTimeout;
            }
            // 外部关闭
            _ = cancel_waiter.wait() => {
                debug!("canceled");
                break CloseReason::Canceled;
            }
        }
    };

    outgoing_task.abort();

    close_reason
}

async fn send_packet_to_incoming(
    packet_writer: &mut impl PacketMutWrite,
    packet: &Option<(Bytes, ServerAddr)>,
) -> io::Result<()> {
    if let Some((data, addr)) = packet {
        packet_writer.write_to_mut(&data[..], addr).await
    } else {
        std::future::pending().await
    }
}

async fn dispatch_outgoing_packet(
    outgoing_socket: Arc<Box<dyn UdpSocket>>,
    mut outgoing_pkt_rx: PacketReceiver,
    timeout_ticker: TimeoutTicker,
) -> Option<CloseReason> {
    while let Some((pkt, addr)) = outgoing_pkt_rx.recv().await {
        match outgoing_socket.send_to(&pkt, addr).await {
            Ok(()) => timeout_ticker.tick(),
            Err(err) => {
                error!(error = ?err, "outgoing socket send error");
                return Some(CloseReason::SockError);
            }
        }
    }

    None
}

async fn listen_outgoing_packet(
    outgoing_socket: Arc<Box<dyn UdpSocket>>,
    incoming_pkt_tx: PacketSender,
    timeout_ticker: TimeoutTicker,
) -> Option<CloseReason> {
    loop {
        let (pkt, addr) = match outgoing_socket.recv_from().await {
            Ok(r) => {
                timeout_ticker.tick();
                r
            }
            Err(err) => {
                error!(error = ?err, "outgoing socket recv error");
                return Some(CloseReason::SockError);
            }
        };

        match incoming_pkt_tx.send((pkt, ServerAddr::SocketAddr(addr))).await {
            Ok(()) => {}
            Err(err) => {
                error!(error = ?err, "incoming pkg sent by channel error");
                return None;
            }
        };
    }
}
