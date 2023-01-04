use std::net::SocketAddr;

use super::*;

use bytes::Bytes;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tracing::{debug, trace, warn};

use crate::{
    net::FlowStat,
    policy::{PacketAction, UdpSocket},
    relay::udprelay::MAXIMUM_UDP_PAYLOAD_SIZE,
    timeout::{TimeoutTicker, TimeoutWaiter},
    transport::StreamConnection,
};

use super::super::{new_trojan_packet_connection, TrojanUdpReader, TrojanUdpWriter};

pub type PacketSender = Sender<(Bytes, ServerAddr)>;
pub type PacketReceiver = Receiver<(Bytes, ServerAddr)>;

pub(super) async fn serve_udp(
    cancel_waiter: &CancelWaiter,
    incoming: impl StreamConnection + 'static,
    peer_addr: Option<SocketAddr>,
    idle_timeout: Duration,
    server_policy: Arc<Box<dyn ServerPolicy>>,
    #[cfg(feature = "statistics")] bu_context: crate::statistics::BuContext,
) -> CloseReason {
    let (outgoing_pkt_tx, outgoing_pkt_rx) = channel(1);
    let (incoming_pkt_tx, incoming_pkt_rx) = channel(1);
    let (close_reason_tx, mut close_reason_rx) = channel(1);

    let timeout_waiter = TimeoutWaiter::new(idle_timeout);

    // 启动处上游数据的任务
    let outgoing_task = {
        let outgoing_socket = match server_policy.create_out_udp_socket().await {
            Ok(s) => s,
            Err(err) => {
                error!(error = ?err, "create outgoing socket error");
                return CloseReason::InternalError;
            }
        };

        tokio::spawn(
            serve_udp_outgoing(
                outgoing_pkt_rx,
                incoming_pkt_tx,
                close_reason_tx.clone(),
                outgoing_socket,
                timeout_waiter.ticker(),
            )
            .in_current_span(),
        )
    };

    #[cfg(feature = "statistics")]
    let _udp_session_guard = crate::statistics::ConnGuard::new(
        bu_context,
        crate::statistics::METRIC_UDP_SESSION,
        Some(crate::statistics::METRIC_UDP_SESSION_TOTAL),
    );

    tokio::pin!(timeout_waiter);

    // 当前任务执行客户端请求分发
    let close_reason = tokio::select! {
        r = serve_udp_incoming(outgoing_pkt_tx, incoming_pkt_rx, incoming, peer_addr, server_policy, timeout_waiter.ticker()) => { r }
        r = close_reason_rx.recv() => {
            match r {
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
            CloseReason::IdleTimeout
        }
        // 外部关闭
        _ = cancel_waiter.wait() => {
            debug!("canceled");
            CloseReason::Canceled
        }
    };

    outgoing_task.abort();

    close_reason
}

// 分发到上游的socket数据
async fn serve_udp_incoming(
    outgoing_pkt_tx: PacketSender,
    incoming_pkt_rx: PacketReceiver,
    incoming: impl StreamConnection + 'static,
    peer_addr: Option<SocketAddr>,
    server_policy: Arc<Box<dyn ServerPolicy>>,
    timeout_ticker: TimeoutTicker,
) -> CloseReason {
    let (incoming_reader, incoming_writer) = new_trojan_packet_connection(incoming);
    let flow_state = server_policy.create_connection_flow_state_udp();
    let flow_state_2 = flow_state.clone();
    tokio::select! {
        r = dispatch_incoming_to_outgoing(incoming_reader, outgoing_pkt_tx, peer_addr, server_policy, flow_state, timeout_ticker) => { r }
        r = dispatch_incoming_from_outgoing(incoming_writer, incoming_pkt_rx, flow_state_2) => { r }
    }
}

async fn dispatch_incoming_to_outgoing<S>(
    mut incoming_reader: TrojanUdpReader<S>,
    outgoing_pkt_tx: PacketSender,
    peer_addr: Option<SocketAddr>,
    server_policy: Arc<Box<dyn ServerPolicy>>,
    flow_state: Option<Arc<FlowStat>>,
    timeout_ticker: TimeoutTicker,
) -> CloseReason
where
    S: StreamConnection + 'static,
{
    let mut buffer = [0u8; MAXIMUM_UDP_PAYLOAD_SIZE];
    let mut client_validated = false;

    loop {
        let (n, addr) = match incoming_reader.read_from(&mut buffer).await {
            Ok(r) => r,
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => {
                debug!("incoming closed");
                return CloseReason::SockClosed;
            }
            Err(err) => {
                error!(error = ?err, "incoming recv error");
                return CloseReason::SockError;
            }
        };

        timeout_ticker.tick();
        let data = Bytes::copy_from_slice(&buffer[..n]);
        if let Some(o) = flow_state.as_ref() {
            o.incr_rx(data.len() as u64);
        }

        let check_peer_addr = if client_validated {
            None
        } else {
            client_validated = true;
            peer_addr
        };

        match server_policy.packet_check(check_peer_addr.as_ref(), &addr).await {
            Err(err) => {
                warn!(target = addr.to_string(), error = ?err, "packet check fail");
                return CloseReason::ClientBlocked;
            }
            Ok(PacketAction::ClientBlocked) => {
                warn!(target = addr.to_string(), "client blocked by ACL rules");
                return CloseReason::ClientBlocked;
            }
            Ok(PacketAction::OutboundBlocked) => {
                warn!(target = addr.to_string(), "outbound blocked by ACL rules");
                return CloseReason::OutboundBlocked;
            }
            Ok(PacketAction::Remote) => {
                let addr_for_log = addr.to_string();
                match outgoing_pkt_tx.send((data, addr)).await {
                    Ok(()) => {}
                    Err(err) => {
                        debug!(target = addr_for_log, error = ?err, "send channel closed");
                    }
                }
            }
        };
    }
}

async fn dispatch_incoming_from_outgoing<S>(
    mut incoming_writer: TrojanUdpWriter<S>,
    mut incoming_pkt_rx: PacketReceiver,
    flow_state: Option<Arc<FlowStat>>,
) -> CloseReason
where
    S: StreamConnection + 'static,
{
    loop {
        let (data, addr) = match incoming_pkt_rx.recv().await {
            Some(r) => r,
            None => {
                error!("incoming_pkt_rx broken");
                return CloseReason::InternalError;
            }
        };

        match incoming_writer.write_to_mut(&data[..], &addr).await {
            Ok(()) => {
                if let Some(o) = flow_state.as_ref() {
                    o.incr_rx(data.len() as u64);
                }
            }
            Err(err) => {
                error!(error = ?err, "incoming send error");
                return CloseReason::SockError;
            }
        }
    }
}

// 分发到上游的socket数据
async fn serve_udp_outgoing(
    mut outgoing_pkt_rx: PacketReceiver,
    mut incoming_pkt_tx: PacketSender,
    close_reason_tx: Sender<CloseReason>,
    outgoing_socket: Box<dyn UdpSocket>,
    timeout_ticker: TimeoutTicker,
) {
    let outgoing_socket_1 = Arc::new(outgoing_socket);
    let outgoing_socket_2 = outgoing_socket_1.clone();

    let r = tokio::select!(
        r = dispatch_outgoing_from_incoming(outgoing_socket_1, &mut outgoing_pkt_rx, timeout_ticker.clone()) => { r }
        r = dispatch_outgoing_to_incoming(outgoing_socket_2, &mut incoming_pkt_tx, timeout_ticker.clone()) => { r }
    );

    if let Some(reason) = r {
        if let Err(err) = close_reason_tx.send(reason).await {
            trace!(error = err.to_string(), "close_reason_tx closed");
        } else {
            // 发送结果成功，则任务等待被动关闭，为了防止没有被释放，通过Sleep一个时间段实现
            tokio::time::sleep(Duration::from_secs(1)).await
        }
    }
}

async fn dispatch_outgoing_from_incoming(
    outgoing_socket: Arc<Box<dyn UdpSocket>>,
    outgoing_pkt_rx: &mut PacketReceiver,
    timeout_ticker: TimeoutTicker,
) -> Option<CloseReason> {
    while let Some((pkt, addr)) = outgoing_pkt_rx.recv().await {
        match outgoing_socket.send_to(&pkt, addr).await {
            Ok(()) => timeout_ticker.tick(),
            Err(_err) => {
                return Some(CloseReason::SockError);
            }
        }
    }

    None
}

async fn dispatch_outgoing_to_incoming(
    outgoing_socket: Arc<Box<dyn UdpSocket>>,
    incoming_pkt_tx: &mut PacketSender,
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
