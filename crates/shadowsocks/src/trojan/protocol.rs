use bytes::BufMut;
use once_cell::sync::Lazy;
use sha2::{Digest, Sha224};
use std::{
    fmt::Write,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub use crate::relay::socks5::{Address, Error};

pub const HASH_STR_LEN: usize = 56;

pub fn password_to_hash(s: &str) -> String {
    let mut hasher = Sha224::new();
    hasher.update(&s.to_string().into_bytes());
    let h = hasher.finalize();
    let mut s = String::with_capacity(HASH_STR_LEN);
    for i in h {
        write!(s, "{:02x}", i).unwrap();
    }
    s
}

const CMD_TCP_CONNECT: u8 = 0x01;
const CMD_UDP_ASSOCIATE: u8 = 0x03;

const CRLF: &[u8; 2] = b"\r\n";

/// ```plain
/// +-----------------------+---------+----------------+---------+----------+
/// | hex(SHA224(password)) |  CRLF   | Trojan Request |  CRLF   | Payload  |
/// +-----------------------+---------+----------------+---------+----------+
/// |          56           | X'0D0A' |    Variable    | X'0D0A' | Variable |
/// +-----------------------+---------+----------------+---------+----------+
///
/// where Trojan Request is a SOCKS5-like request:
///
/// +-----+------+----------+----------+
/// | CMD | ATYP | DST.ADDR | DST.PORT |
/// +-----+------+----------+----------+
/// |  1  |  1   | Variable |    2     |
/// +-----+------+----------+----------+
///
/// where:
///
/// o  CMD
/// o  CONNECT X'01'
/// o  UDP ASSOCIATE X'03'
/// o  ATYP address type of following address
/// o  IP V4 address: X'01'
/// o  DOMAINNAME: X'03'
/// o  IP V6 address: X'04'
/// o  DST.ADDR desired destination address
/// o  DST.PORT desired destination port in network octet order
/// ```
pub enum RequestHeader {
    TcpConnect(Arc<[u8; HASH_STR_LEN]>, Address),
    UdpAssociate(Arc<[u8; HASH_STR_LEN]>),
}

static UDP_DUMMY_ADDR: Lazy<Address> =
    Lazy::new(|| Address::SocketAddress(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 0)));

impl RequestHeader {
    pub async fn read_from<R>(stream: &mut R, valid_hash: &[u8]) -> Result<Self, Error>
    where
        R: AsyncRead + Unpin,
    {
        let mut hash_buf = [0u8; HASH_STR_LEN];
        let len = stream.read_exact(&mut hash_buf).await?;
        assert!(len == HASH_STR_LEN);

        if valid_hash != hash_buf {
            return Err(Error::PasswdAuthInvalidRequest);
        }

        let mut crlf_buf = [0u8; 2];
        let mut cmd_buf = [0u8; 1];

        stream.read_exact(&mut crlf_buf).await?;
        stream.read_exact(&mut cmd_buf).await?;
        let addr = Address::read_from(stream).await?;
        stream.read_exact(&mut crlf_buf).await?;

        match cmd_buf[0] {
            CMD_TCP_CONNECT => Ok(Self::TcpConnect(Arc::new(hash_buf), addr)),
            CMD_UDP_ASSOCIATE => Ok(Self::UdpAssociate(Arc::new(hash_buf))),
            _ => Err(Error::UnsupportedCommand(cmd_buf[0])),
        }
    }

    #[inline]
    pub fn serialized_len(&self) -> usize {
        let addr = match self {
            RequestHeader::TcpConnect(_hash, addr) => addr,
            RequestHeader::UdpAssociate(_hash) => &UDP_DUMMY_ADDR,
        };

        HASH_STR_LEN + 2 + 1 + addr.serialized_len() + 2
    }

    #[inline]
    pub fn write_to_buf<B: BufMut>(&self, cursor: &mut B) {
        let (hash, addr, cmd) = match self {
            RequestHeader::TcpConnect(hash, addr) => (hash, addr, CMD_TCP_CONNECT),
            RequestHeader::UdpAssociate(hash) => (hash, &UDP_DUMMY_ADDR as &Address, CMD_UDP_ASSOCIATE),
        };

        cursor.put_slice(hash.as_ref());
        cursor.put_slice(CRLF);
        cursor.put_u8(cmd);
        addr.write_to_buf(cursor);
        cursor.put_slice(CRLF);
    }
}

/// ```plain
/// +------+----------+----------+--------+---------+----------+
/// | ATYP | DST.ADDR | DST.PORT | Length |  CRLF   | Payload  |
/// +------+----------+----------+--------+---------+----------+
/// |  1   | Variable |    2     |   2    | X'0D0A' | Variable |
/// +------+----------+----------+--------+---------+----------+
/// ```
pub struct UdpHeader {
    pub address: Address,
    pub payload_len: u16,
}

impl UdpHeader {
    #[inline]
    pub fn new(addr: Address, payload_len: usize) -> Self {
        Self {
            address: addr,
            payload_len: payload_len as u16,
        }
    }

    pub async fn read_from<R>(stream: &mut R) -> io::Result<Self>
    where
        R: AsyncRead + Unpin,
    {
        let addr = Address::read_from(stream).await?;
        let len = stream.read_u16().await?;

        let mut buf = [0u8; 2];
        stream.read_exact(&mut buf).await?;

        if buf[0] != 0x0D || buf[1] != 0x0A {
            return Err(io::Error::new(io::ErrorKind::Other, "protocol sep mismatch"));
        }

        Ok(Self {
            address: addr,
            payload_len: len,
        })
    }

    pub async fn write_to<W>(&self, w: &mut W) -> io::Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        let mut buf = Vec::with_capacity(self.address.serialized_len() + 2 + 1);
        let cursor = &mut buf;
        self.address.write_to_buf(cursor);
        cursor.put_u16(self.payload_len);
        cursor.put_slice(b"\r\n");
        let _ = w.write(&buf).await?;
        Ok(())
    }
}
