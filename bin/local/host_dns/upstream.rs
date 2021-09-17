use byteorder::{BigEndian, ByteOrder};
use bytes::{BufMut, BytesMut};
use log::trace;
use rand::{thread_rng, Rng};
use std::{io, net::SocketAddr};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    time::{self, Duration},
};

use trust_dns_resolver::proto::{
    error::{ProtoError, ProtoErrorKind},
    op::Message,
};

#[allow(clippy::large_enum_variant)]
pub enum DnsClient {
    Tcp { stream: TcpStream },
    Udp { socket: UdpSocket },
}

impl DnsClient {
    /// Connect to local provided TCP DNS server
    pub async fn connect_tcp(ns: SocketAddr) -> io::Result<DnsClient> {
        let stream = TcpStream::connect(&ns).await?;
        Ok(DnsClient::Tcp { stream })
    }

    /// Connect to local provided UDP DNS server
    pub async fn connect_udp(ns: SocketAddr) -> io::Result<DnsClient> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        socket.connect(&ns).await?;
        Ok(DnsClient::Udp { socket })
    }

    /// Make a DNS lookup with timeout
    pub async fn lookup_timeout(&mut self, mut msg: Message, timeout: Duration) -> Result<Message, ProtoError> {
        match time::timeout(timeout, self.inner_lookup(&mut msg)).await {
            Ok(Ok(msg)) => Ok(msg),
            Ok(Err(error)) => Err(error),
            Err(..) => Err(ProtoErrorKind::Timeout.into()),
        }
    }

    async fn inner_lookup(&mut self, msg: &mut Message) -> Result<Message, ProtoError> {
        // Make a random ID
        msg.set_id(thread_rng().gen());

        trace!("host DNS lookup {:?}", msg);

        match *self {
            DnsClient::Tcp { ref mut stream } => stream_query(stream, msg).await,
            DnsClient::Udp { ref socket } => {
                let bytes = msg.to_vec()?;
                socket.send(&bytes).await?;

                let mut recv_buf = [0u8; 256];
                let n = socket.recv(&mut recv_buf).await?;

                Message::from_vec(&recv_buf[..n])
            }
        }
    }
}

pub async fn stream_query<S>(stream: &mut S, r: &Message) -> Result<Message, ProtoError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut req_bytes = r.to_vec()?;

    // Prepend length
    let length = req_bytes.len();
    req_bytes.resize(length + 2, 0);
    req_bytes.copy_within(..length, 2);
    BigEndian::write_u16(&mut req_bytes[0..2], length as u16);

    stream.write_all(&req_bytes).await?;

    // Read response, [LENGTH][Message]
    let mut length_buf = [0u8; 2];
    stream.read_exact(&mut length_buf).await?;

    let length = BigEndian::read_u16(&length_buf);
    let mut rsp_bytes = BytesMut::with_capacity(length as usize);
    unsafe {
        rsp_bytes.advance_mut(length as usize);
    }
    stream.read_exact(&mut rsp_bytes).await?;

    Message::from_vec(&rsp_bytes)
}
