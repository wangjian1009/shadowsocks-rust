use super::super::super::protocol::{Address, Command};
use super::{stream, Connection, UdpSessionCloseReason, UdpSessionSource};
use bytes::{Bytes, BytesMut};
use quinn::{RecvStream, SendStream, VarInt};
use std::io::Error as IoError;
use thiserror::Error;
use tracing::{debug, error, info_span, trace, Instrument};

use crate::canceler::CancelWaiter;
use crate::ServerAddr;

impl Connection {
    pub async fn process_uni_stream(&self, mut stream: RecvStream) -> Result<(), DispatchError> {
        let cmd = Command::read_from(&mut stream).await?;
        trace!("cmd: {:?}", cmd);

        if let Command::Authenticate { digest } = cmd {
            if self.token.contains(&digest) {
                debug!("authentication success");

                self.is_authenticated.set_authenticated();
                self.is_authenticated.wake();
                return Ok(());
            } else {
                error!("authentication fail");
                return Err(DispatchError::AuthenticationFailed);
            }
        }

        if self.is_authenticated.clone().await {
            match cmd {
                Command::Authenticate { .. } => unreachable!(),
                Command::Packet { assoc_id, len, addr } => {
                    let addr = ServerAddr::from(addr);
                    let mut buf = vec![0; len as usize];
                    if let Err(err) = stream.read_exact(&mut buf).await {
                        debug!(error = ?err, "read packet data");
                        return Ok(());
                    }

                    let pkt = Bytes::from(buf);

                    self.flow_state.as_ref().map(|f| f.incr_rx(pkt.len() as u64));
                    #[cfg(feature = "statistics")]
                    self.bu_context.count_traffic(
                        crate::statistics::METRIC_TRAFFIC_BU_TOTAL,
                        pkt.len() as u64,
                        crate::statistics::TrafficNet::Udp,
                        crate::statistics::TrafficWay::Recv,
                    );

                    if let Err(err) = self
                        .udp_sessions
                        .send_to_outgoing(
                            assoc_id,
                            UdpSessionSource::UniStream,
                            pkt,
                            addr,
                            self.controller.remote_address(),
                            self.server_policy.clone(),
                            #[cfg(feature = "statistics")]
                            self.bu_context.clone(),
                        )
                        .await
                    {
                        error!(error = ?err, "send to outgoing error");
                        return Err(DispatchError::Io(err));
                    }

                    Ok(())
                }
                Command::Dissociate { assoc_id } => {
                    let _ = self
                        .udp_sessions
                        .dissociate(assoc_id, UdpSessionCloseReason::ClientClose)
                        .await;
                    Ok(())
                }
                Command::Heartbeat => {
                    trace!("heartbeat");
                    Ok(())
                }
                _ => Err(DispatchError::BadCommand),
            }
        } else {
            Err(DispatchError::AuthenticationTimeout)
        }
    }

    pub async fn process_bi_stream(
        &self,
        send: SendStream,
        mut recv: RecvStream,
        waiter: CancelWaiter,
    ) -> Result<(), DispatchError> {
        let cmd = Command::read_from(&mut recv).await?;
        let rmt_addr = self.controller.remote_address();

        #[cfg(feature = "statistics")]
        let _in_conn_guard = crate::statistics::ConnGuard::new(
            self.bu_context.clone(),
            crate::statistics::METRIC_TCP_CONN_IN,
            Some(crate::statistics::METRIC_TCP_CONN_IN_TOTAL),
        );

        if self.is_authenticated.clone().await {
            match cmd {
                Command::Connect { addr } => {
                    let addr = ServerAddr::from(addr);
                    let span = info_span!("connection", target = addr.to_string());
                    async move {
                        #[cfg(feature = "statistics")]
                        let _in_conn_guard = _in_conn_guard;

                        tokio::select! {
                            _ = stream::connect(
                                self.server_policy.clone(),
                                &rmt_addr,
                                send,
                                recv,
                                addr,
                                self.flow_state.clone(),
                                self.idle_timeout.clone(),
                                #[cfg(feature = "statistics")] self.bu_context.clone(),
                            ) => {}
                            _ = waiter.wait() => {}
                        }
                    }
                    .instrument(span.or_current())
                    .await;

                    Ok(())
                }
                _ => {
                    #[cfg(feature = "statistics")]
                    self.bu_context.increment_conn_error("tuic.bad-command");

                    Err(DispatchError::BadCommand)
                }
            }
        } else {
            #[cfg(feature = "statistics")]
            self.bu_context.increment_conn_error("tuic.auth-timeout");

            Err(DispatchError::AuthenticationTimeout)
        }
    }

    pub async fn process_datagram(&self, datagram: Bytes) -> Result<(), DispatchError> {
        let cmd = Command::read_from(&mut datagram.as_ref()).await?;
        let cmd_len = cmd.serialized_len();

        if self.is_authenticated.clone().await {
            match cmd {
                Command::Packet { assoc_id, addr, .. } => {
                    let addr = ServerAddr::from(addr);
                    let pkt = datagram.slice(cmd_len..);

                    self.flow_state.as_ref().map(|f| f.incr_rx(pkt.len() as u64));
                    #[cfg(feature = "statistics")]
                    self.bu_context.count_traffic(
                        crate::statistics::METRIC_TRAFFIC_BU_TOTAL,
                        pkt.len() as u64,
                        crate::statistics::TrafficNet::Udp,
                        crate::statistics::TrafficWay::Recv,
                    );

                    if let Err(err) = self
                        .udp_sessions
                        .send_to_outgoing(
                            assoc_id,
                            UdpSessionSource::Datagram,
                            pkt,
                            addr,
                            self.controller.remote_address(),
                            self.server_policy.clone(),
                            #[cfg(feature = "statistics")]
                            self.bu_context.clone(),
                        )
                        .await
                    {
                        error!(error = ?err, "send to outgoing error");
                        return Err(DispatchError::Io(err));
                    }

                    Ok(())
                }
                _ => Err(DispatchError::BadCommand),
            }
        } else {
            Err(DispatchError::AuthenticationTimeout)
        }
    }

    pub async fn process_received_udp_packet(
        &self,
        assoc_id: u32,
        pkt: Bytes,
        addr: ServerAddr,
    ) -> Result<(), DispatchError> {
        let (source, span) = match self.udp_sessions.find_session(assoc_id) {
            Some(r) => r,
            None => {
                debug!(assoc_id, "send to incoming: session not found");
                return Ok(());
            }
        };

        async move {
            match source {
                UdpSessionSource::UniStream => {
                    let mut stream = match self.controller.open_uni().await {
                        Ok(s) => s,
                        Err(err) => {
                            error!(error = ?err, "send to incoming: open stream error");
                            return Ok(());
                        }
                    };

                    let cmd = Command::new_packet(assoc_id, pkt.len() as u16, Address::from(addr));
                    if let Err(err) = cmd.write_to(&mut stream).await {
                        error!(error = ?err, "write cmd error");
                        return Ok(());
                    }

                    if let Err(err) = stream.write_all(&pkt).await {
                        error!(error = ?err, "write_all error");
                        return Ok(());
                    }

                    if let Err(err) = stream.finish().await {
                        error!(error = ?err, "write_all error");
                        return Ok(());
                    }

                    self.flow_state.as_ref().map(|f| f.incr_tx(pkt.len() as u64));
                    #[cfg(feature = "statistics")]
                    self.bu_context.count_traffic(
                        crate::statistics::METRIC_TRAFFIC_BU_TOTAL,
                        pkt.len() as u64,
                        crate::statistics::TrafficNet::Udp,
                        crate::statistics::TrafficWay::Send,
                    )
                }
                UdpSessionSource::Datagram => {
                    let cmd = Command::new_packet(assoc_id, pkt.len() as u16, Address::from(addr));

                    let mut buf = BytesMut::with_capacity(cmd.serialized_len());
                    cmd.write_to_buf(&mut buf);
                    buf.extend_from_slice(&pkt);

                    let pkt = buf.freeze();
                    let len = pkt.len();

                    if let Err(err) = self.controller.send_datagram(pkt) {
                        debug!(error = ?err, "send to incoming error");
                        return Ok(());
                    }

                    self.flow_state.as_ref().map(|f| f.incr_tx(len as u64));
                    #[cfg(feature = "statistics")]
                    self.bu_context.count_traffic(
                        crate::statistics::METRIC_TRAFFIC_BU_TOTAL,
                        len as u64,
                        crate::statistics::TrafficNet::Udp,
                        crate::statistics::TrafficWay::Send,
                    )
                }
            }

            Ok(())
        }
        .instrument(span)
        .await
    }
}

#[derive(Error, Debug)]
pub enum DispatchError {
    #[error(transparent)]
    Io(#[from] IoError),
    #[error("authentication failed")]
    AuthenticationFailed,
    #[error("authentication timeout")]
    AuthenticationTimeout,
    #[error("bad command")]
    BadCommand,
    #[error("idle timeout")]
    IdleTimeout,
    #[error("shutdown")]
    Shutdown,
}

impl DispatchError {
    const CODE_PROTOCOL: VarInt = VarInt::from_u32(0xfffffff0);
    const CODE_AUTHENTICATION_FAILED: VarInt = VarInt::from_u32(0xfffffff1);
    const CODE_AUTHENTICATION_TIMEOUT: VarInt = VarInt::from_u32(0xfffffff2);
    const CODE_BAD_COMMAND: VarInt = VarInt::from_u32(0xfffffff3);
    const CODE_IDLE_TIMEOUT: VarInt = VarInt::from_u32(0xfffffff4);
    const CODE_SHUTDOWN: VarInt = VarInt::from_u32(0xfffffff5);

    pub fn as_error_code(&self) -> VarInt {
        match self {
            Self::Io(_) => Self::CODE_PROTOCOL,
            Self::AuthenticationFailed => Self::CODE_AUTHENTICATION_FAILED,
            Self::AuthenticationTimeout => Self::CODE_AUTHENTICATION_TIMEOUT,
            Self::BadCommand => Self::CODE_BAD_COMMAND,
            Self::IdleTimeout => Self::CODE_IDLE_TIMEOUT,
            Self::Shutdown => Self::CODE_SHUTDOWN,
        }
    }
}
