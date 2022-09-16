use super::super::super::protocol::{Address, Command};
use super::udp::UdpSessionMap;
use bytes::{Bytes, BytesMut};
use cfg_if::cfg_if;
use quinn::{
    Connection as QuinnConnection, ConnectionError, ReadExactError, RecvStream, SendDatagramError, SendStream,
    WriteError,
};

use std::{
    io::{Error as IoError, IoSlice},
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use thiserror::Error;
use tokio::io::{self, AsyncRead, AsyncWrite, ReadBuf};

use crate::{
    net::FlowStat,
    policy::{PacketAction, ServerPolicy, StreamAction},
    transport::MonTraffic,
};

#[cfg(feature = "rate-limit")]
use crate::transport::RateLimitedStream;

pub async fn connect(
    server_policy: Arc<Box<dyn ServerPolicy>>,
    rmt_addr: &SocketAddr,
    mut send: SendStream,
    recv: RecvStream,
    addr: Address,
    flow_state: Option<Arc<FlowStat>>,
) -> Result<(), TaskError> {
    let addr2 = match addr.clone() {
        Address::DomainAddress(h, p) => crate::relay::Address::DomainNameAddress(h, p),
        Address::SocketAddress(s) => crate::relay::Address::SocketAddress(s),
    };

    match server_policy.stream_check(rmt_addr, &addr2).await? {
        StreamAction::ClientBlocked => Err(TaskError::Io(io::Error::new(
            io::ErrorKind::Other,
            format!("client {} blocked by ACL rules", rmt_addr),
        ))),
        StreamAction::OutboundBlocked => Err(TaskError::Io(io::Error::new(
            io::ErrorKind::Other,
            format!("outbound {} blocked by ACL rules", addr),
        ))),
        StreamAction::ConnectionLimited => Err(TaskError::Io(io::Error::new(
            io::ErrorKind::Other,
            format!("client {} blocked by count limit", addr),
        ))),
        StreamAction::Remote {
            connection_guard: _,
            #[cfg(feature = "rate-limit")]
            rate_limit,
        } => {
            #[allow(unused_mut)]
            let (mut target, _guard) = match server_policy.create_out_connection(&addr2).await {
                Ok(s) => {
                    let resp = Command::new_response(true);
                    resp.write_to(&mut send).await?;
                    s
                }
                Err(err) => {
                    let resp = Command::new_response(false);
                    resp.write_to(&mut send).await?;
                    send.finish().await?;
                    return Err(TaskError::Io(err));
                }
            };

            let flow_state_tx = flow_state.clone();

            #[allow(unused_mut)]
            let mut tunnel = MonTraffic::new(BiStream(send, recv), flow_state_tx, flow_state.clone());

            cfg_if! {
                if #[cfg(feature = "rate-limit")] {
                    let mut tunnel =
                        RateLimitedStream::from_stream(tunnel, rate_limit.clone());

                    let mut target =
                        RateLimitedStream::from_stream(target, rate_limit);
                }
            }

            io::copy_bidirectional(&mut target, &mut tunnel).await?;

            Ok(())
        }
        StreamAction::Local { processor } => {
            let resp = Command::new_response(true);
            resp.write_to(&mut send).await?;

            let flow_state_tx = flow_state.clone();
            let flow_state_rx = flow_state;
            let send = MonTraffic::new(send, flow_state_tx, None);
            let recv = MonTraffic::new(recv, None, flow_state_rx);

            processor
                .process(
                    Box::new(recv) as Box<dyn AsyncRead + Send + Unpin>,
                    Box::new(send) as Box<dyn AsyncWrite + Send + Unpin>,
                )
                .await
                .map_err(|e| TaskError::Io(e))?;

            Ok(())
        }
    }
}

pub async fn packet_from_uni_stream(
    server_policy: Arc<Box<dyn ServerPolicy>>,
    mut stream: RecvStream,
    udp_sessions: Arc<UdpSessionMap>,
    assoc_id: u32,
    len: u16,
    addr: Address,
    src_addr: SocketAddr,
    flow_state: Option<Arc<FlowStat>>,
) -> Result<(), TaskError> {
    let mut buf = vec![0; len as usize];
    stream.read_exact(&mut buf).await?;

    let addr2 = match addr.clone() {
        Address::DomainAddress(h, p) => crate::relay::Address::DomainNameAddress(h, p),
        Address::SocketAddress(s) => crate::relay::Address::SocketAddress(s),
    };

    match server_policy.packet_check(&src_addr, &addr2).await? {
        PacketAction::ClientBlocked => Err(TaskError::Io(io::Error::new(
            io::ErrorKind::Other,
            format!("client {} blocked by ACL rules", src_addr),
        ))),
        PacketAction::OutboundBlocked => Err(TaskError::Io(io::Error::new(
            io::ErrorKind::Other,
            format!("outbound {} blocked by ACL rules", addr),
        ))),
        PacketAction::Remote => {
            let pkt = Bytes::from(buf);
            udp_sessions.send(assoc_id, pkt, addr, src_addr).await?;

            flow_state.map(|f| f.incr_rx(len as u64));

            Ok(())
        }
    }
}

pub async fn packet_from_datagram(
    server_policy: Arc<Box<dyn ServerPolicy>>,
    pkt: Bytes,
    udp_sessions: Arc<UdpSessionMap>,
    assoc_id: u32,
    addr: Address,
    src_addr: SocketAddr,
    flow_state: Option<Arc<FlowStat>>,
) -> Result<(), TaskError> {
    let addr2 = match addr.clone() {
        Address::DomainAddress(h, p) => crate::relay::Address::DomainNameAddress(h, p),
        Address::SocketAddress(s) => crate::relay::Address::SocketAddress(s),
    };

    match server_policy.packet_check(&src_addr, &addr2).await? {
        PacketAction::ClientBlocked => Err(TaskError::Io(io::Error::new(
            io::ErrorKind::Other,
            format!("client {} blocked by ACL rules", src_addr),
        ))),
        PacketAction::OutboundBlocked => Err(TaskError::Io(io::Error::new(
            io::ErrorKind::Other,
            format!("outbound {} blocked by ACL rules", addr),
        ))),
        PacketAction::Remote => {
            let len = pkt.len();
            udp_sessions.send(assoc_id, pkt, addr, src_addr).await?;

            flow_state.map(|f| f.incr_rx(len as u64));

            Ok(())
        }
    }
}

pub async fn packet_to_uni_stream(
    conn: QuinnConnection,
    assoc_id: u32,
    pkt: Bytes,
    addr: Address,
    flow_state: Option<Arc<FlowStat>>,
) -> Result<(), TaskError> {
    let mut stream = conn.open_uni().await?;

    let cmd = Command::new_packet(assoc_id, pkt.len() as u16, addr);
    cmd.write_to(&mut stream).await?;
    stream.write_all(&pkt).await?;
    stream.finish().await?;

    flow_state.map(|f| f.incr_tx(pkt.len() as u64));

    Ok(())
}

pub async fn packet_to_datagram(
    conn: QuinnConnection,
    assoc_id: u32,
    pkt: Bytes,
    addr: Address,
    flow_state: Option<Arc<FlowStat>>,
) -> Result<(), TaskError> {
    let cmd = Command::new_packet(assoc_id, pkt.len() as u16, addr);

    let mut buf = BytesMut::with_capacity(cmd.serialized_len());
    cmd.write_to_buf(&mut buf);
    buf.extend_from_slice(&pkt);

    let pkt = buf.freeze();
    let len = pkt.len();
    conn.send_datagram(pkt)?;

    flow_state.map(|f| f.incr_tx(len as u64));

    Ok(())
}

pub async fn dissociate(
    udp_sessions: Arc<UdpSessionMap>,
    assoc_id: u32,
    src_addr: SocketAddr,
) -> Result<(), TaskError> {
    udp_sessions.dissociate(assoc_id, src_addr);
    Ok(())
}

struct BiStream(SendStream, RecvStream);

impl AsyncRead for BiStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<Result<(), IoError>> {
        Pin::new(&mut self.1).poll_read(cx, buf)
    }
}

impl AsyncWrite for BiStream {
    #[inline]
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, IoError>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    #[inline]
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<Result<usize, IoError>> {
        Pin::new(&mut self.0).poll_write_vectored(cx, bufs)
    }

    #[inline]
    fn is_write_vectored(&self) -> bool {
        self.0.is_write_vectored()
    }

    #[inline]
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), IoError>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    #[inline]
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), IoError>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

#[derive(Error, Debug)]
pub enum TaskError {
    #[error(transparent)]
    Io(#[from] IoError),
    #[error(transparent)]
    Connection(#[from] ConnectionError),
    #[error(transparent)]
    ReadStream(#[from] ReadExactError),
    #[error(transparent)]
    WriteStream(#[from] WriteError),
    #[error(transparent)]
    SendDatagram(#[from] SendDatagramError),
}
