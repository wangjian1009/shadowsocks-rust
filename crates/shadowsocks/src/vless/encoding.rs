use crate::vless::common::UUID;

use super::{new_error, protocol, protocol::Address};
use std::{
    io,
    slice,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
};

use bytes::BufMut;
use tokio::io::{AsyncRead, AsyncReadExt};

enum AddressType {
    IPv4 = 1,
    IPv6 = 3,
    Domain = 2,
}

pub fn request_header_serialized_len(
    request: &protocol::RequestHeader,
    _request_addons: &Option<protocol::Addons>,
) -> usize {
    let mut sz = 1 + 16 + 1 + 1;

    if let Some(address) = request.address.as_ref() {
        match address {
            Address::SocketAddress(addr) => match addr {
                SocketAddr::V4(..) => sz += 2 + 4,
                SocketAddr::V6(..) => sz += 2 + 16,
            },
            Address::DomainNameAddress(host, _port) => sz += 2 + host.len(),
        }
    }

    sz
}

pub fn encode_request_header<W>(
    w: &mut W,
    request: &protocol::RequestHeader,
    request_addons: &Option<protocol::Addons>,
) -> io::Result<usize>
where
    W: BufMut + Unpin,
{
    let mut writed: usize = 0;
    
    w.put_u8(request.version);
    writed += 1;
    
    w.put_slice(request.user.bytes());
    writed += request.user.bytes().len();

    writed += encode_header_addons(w, &request_addons)?;

    w.put_u8(request.command as u8);
    writed += 1;

    if request.command != protocol::RequestCommand::Mux {
        if let Some(address) = request.address.as_ref() {
            writed += encode_address(w, address)?;
        } else {
            return Err(new_error(format!("{:?} request no address", request.command)));
        }
    }

    Ok(writed)
}

pub async fn decode_request_header<R>(
    stream: &mut R,
) -> io::Result<(protocol::RequestHeader, Option<protocol::Addons>, bool)>
where
    R: AsyncRead + Unpin,
{
    let version = stream.read_u8().await?;

    match version {
        0 => {
            let mut id = vec![0u8; 16];
            stream.read_exact(&mut id).await?;
            let id = UUID::parse_bytes(&id)?;

            let addons = decode_header_addons(stream).await?;

            let command = stream.read_u8().await?;
            let command = match command {
                0x01 => protocol::RequestCommand::TCP,
                0x02 => protocol::RequestCommand::UDP,
                0x03 => protocol::RequestCommand::Mux,
                _ => {
                    return Err(new_error(format!("decode request header: invalid cmd {}", command)));
                }
            };

            let mut address = None;
            if command != protocol::RequestCommand::Mux {
                address = Some(decode_address(stream).await?);
            }

            let request = protocol::RequestHeader {
                version,
                command,
                address,
                user: id,
            };

            Ok((request, addons, false))
        }
        _ => Err(new_error(format!(
            "decode request header: invalid request version {}",
            version
        ))),
    }
}

pub fn encode_response_header<W>(
    w: &mut W,
    request_version: u8,
    request_addons: &Option<protocol::Addons>,
) -> io::Result<usize>
where
    W: BufMut + Unpin,
{
    let mut writed: usize = 0;

    w.put_u8(request_version);
    writed += 1;

    writed += encode_header_addons(w, &request_addons)?;
    
    Ok(writed)
}

pub async fn decode_response_header<R>(
    stream: &mut R,
) -> io::Result<Option<protocol::Addons>>
where
    R: AsyncRead + Unpin,
{
    let version = stream.read_u8().await?;

    match version {
        0 => {
            let addons = decode_header_addons(stream).await?;
            Ok(addons)
        }
        _ => Err(new_error(format!(
            "decode response header: invalid request version {}",
            version
        ))),
    }
}

#[inline]
fn encode_header_addons<W>(w: &mut W, addons: &Option<protocol::Addons>) -> io::Result<usize>
where
    W: BufMut + Unpin,
{
    let mut writed = 0;
    
    match addons {
        None => {
            w.put_u8(0);
            writed += 1;
        },
        Some(..) => return Err(new_error("encode request addons: not support addon")),
    }

    Ok(writed)
}

#[inline]
async fn decode_header_addons<R>(stream: &mut R) -> io::Result<Option<protocol::Addons>>
where
    R: AsyncRead + Unpin,
{
    let addons_len = stream.read_u8().await?;

    if addons_len > 0 {
        let mut buffer = vec![0u8, addons_len];
        stream.read_exact(&mut buffer).await?;
        // 暂时不支持Addons
    }

    Ok(None)
}

#[inline]
fn encode_address<W>(w: &mut W, address: &protocol::Address) -> io::Result<usize>
where
    W: BufMut + Unpin,
{
    let mut writed: usize  = 0;

    match address {
        Address::SocketAddress(addr) => match addr {
            SocketAddr::V4(addr) => {
                w.put_u16(addr.port());
                w.put_u8(AddressType::IPv4 as u8);
                w.put_slice(&addr.ip().octets());
                writed += 2 + 1 + addr.ip().octets().len();
            }
            SocketAddr::V6(addr) => {
                w.put_u16(addr.port());
                w.put_u8(AddressType::IPv6 as u8);
                w.put_slice(&addr.ip().octets());
                writed += 2 + 1 + addr.ip().octets().len();
            }
        },
        Address::DomainNameAddress(host, port) => {
            w.put_u16(port.clone());
            w.put_u8(AddressType::Domain as u8);
            w.put_u8(host.len() as u8);
            w.put_slice(host.as_bytes());
            writed += 2 + 1 + 1 + host.as_bytes().len();
        }
    }

    Ok(writed)
}

#[inline]
async fn decode_address<R>(stream: &mut R) -> io::Result<protocol::Address>
where
    R: AsyncRead + Unpin,
{
    let port = stream.read_u16().await?;

    let addr_type = stream.read_u8().await?;

    match addr_type {
        1 /*AddressType::IPv4*/ => {
            let mut buf = [0u8; 4];
            stream.read_exact(&mut buf).await?;

            let v4addr = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);

            Ok(Address::SocketAddress(SocketAddr::V4(SocketAddrV4::new(v4addr, port))))
        }
        3 /*AddressType::IPv6*/ => {
            let mut buf = [0u8; 16];
            stream.read_exact(&mut buf).await?;

            let buf: &[u16] = unsafe { slice::from_raw_parts(buf.as_ptr() as *const _, 9) };
            
            let v6addr = Ipv6Addr::new(
                u16::from_be(buf[0]),
                u16::from_be(buf[1]),
                u16::from_be(buf[2]),
                u16::from_be(buf[3]),
                u16::from_be(buf[4]),
                u16::from_be(buf[5]),
                u16::from_be(buf[6]),
                u16::from_be(buf[7]),
            );

            Ok(Address::SocketAddress(SocketAddr::V6(SocketAddrV6::new(v6addr, port, 0, 0))))
        }
        2 /*AddressType::Domain*/ => {
            let addr_len = stream.read_u8().await?;
            let mut addr_buf = vec![0u8; addr_len as usize];
            stream.read_exact(&mut addr_buf).await?;
            let addr = String::from_utf8(addr_buf).map_err(|e| new_error(format!("decode address: {}", e)))?;
            Ok(protocol::Address::DomainNameAddress(addr, port))
        }
        _ => Err(new_error(format!("decode address: invalid address type {}", addr_type))),
    }
}

#[cfg(test)]
mod test {
    use super::{super::common::UUID, *};
    use std::{io::Cursor, str::FromStr};

    #[tokio::test]
    async fn test_address_ipv4() {
        let _ = env_logger::builder()
            .filter_level(log::LevelFilter::Trace)
            .is_test(true)
            .try_init();

        let bin_address = [
            0x1, 0xbb, 0x1, 0x1, 0x2, 0x3, 0x4
        ];

        let address = protocol::Address::from_str("1.2.3.4:443").unwrap();
        let mut buffer = Vec::new();
        assert_matches!(encode_address(&mut buffer, &address), Ok(7));

        assert_eq!(buffer[..], bin_address);

        let r = decode_address(&mut Cursor::new(&bin_address)).await;
        assert_matches!(r, Ok(..));

        let rebuild_address = r.unwrap();

        assert_eq!(rebuild_address, address);
    }
    
    #[tokio::test]
    async fn test_address_ipv6() {
        let _ = env_logger::builder()
            .filter_level(log::LevelFilter::Trace)
            .is_test(true)
            .try_init();

        let bin_address = [
            0x1, 0xbb, 0x3, 0x20, 0x1, 0x48, 0x60, 0x0, 0x0, 0x20, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x68
        ];

        let address = protocol::Address::from_str("[2001:4860:0:2001::68]:443").unwrap();
        let mut buffer = Vec::new();
        assert_matches!(encode_address(&mut buffer, &address), Ok(19));

        assert_eq!(buffer[..], bin_address);

        let r = decode_address(&mut Cursor::new(&bin_address)).await;
        assert_matches!(r, Ok(..));

        let rebuild_address = r.unwrap();

        assert_eq!(rebuild_address, address);
    }
    
    #[tokio::test]
    async fn test_compact_domain() {
        let _ = env_logger::builder()
            .filter_level(log::LevelFilter::Trace)
            .is_test(true)
            .try_init();

        let bin_packet = [
            0x0, 0xed, 0x6a, 0x11, 0xa3, 0x7d, 0xd9, 0x70, 0x69, 0x55, 0xbb, 0x92, 0x4c, 0x93, 0x6c, 0xbe, 0x71, 0x0,
            0x1, 0x1, 0xbb, 0x2, 0xd, 0x77, 0x77, 0x77, 0x2e, 0x76, 0x32, 0x66, 0x6c, 0x79, 0x2e, 0x6f, 0x72, 0x67,
        ];

        let uuid = UUID::parse_bytes(&[
            0xed, 0x6a, 0x11, 0xa3, 0x7d, 0xd9, 0x70, 0x69, 0x55, 0xbb, 0x92, 0x4c, 0x93, 0x6c, 0xbe, 0x71,
        ])
        .unwrap();

        let request = protocol::RequestHeader {
            version: 0,
            command: protocol::RequestCommand::TCP,
            address: Some(protocol::Address::DomainNameAddress("www.v2fly.org".to_string(), 443)),
            user: uuid,
        };

        let addons = None;

        let mut buffer = Vec::new();
        assert_matches!(encode_request_header(&mut buffer, &request, &addons), Ok(36));

        assert_eq!(buffer[..], bin_packet);

        let r = decode_request_header(&mut Cursor::new(&bin_packet)).await;
        assert_matches!(r, Ok(..));

        let (rebuild_request, rebuild_addons, _b) = r.unwrap();

        assert_eq!(rebuild_request, request);
        assert_eq!(rebuild_addons, addons);
    }

    #[tokio::test]
    async fn test_request_serialization() {
        let id = UUID::new();

        let expected_request = protocol::RequestHeader {
            version: 0,
            command: protocol::RequestCommand::TCP,
            address: Some(protocol::Address::DomainNameAddress("www.v2fly.org".to_string(), 443)),
            user: id.clone(),
        };

        let expected_addons = None;

        let mut buffer = Vec::new();
        assert_matches!(
            encode_request_header(&mut buffer, &expected_request, &expected_addons),
            Ok(36)
        );

        let r = decode_request_header(&mut Cursor::new(&mut buffer[..])).await;
        assert_matches!(r, Ok(..));

        let (request, addons, _v) = r.unwrap();
        assert_eq!(request, expected_request);
        assert_eq!(addons, expected_addons);
    }
}
