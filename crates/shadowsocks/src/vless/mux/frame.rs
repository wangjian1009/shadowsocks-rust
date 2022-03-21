use std::{fmt, io};

use bytes::BufMut;
use tokio::io::{AsyncRead, AsyncReadExt};

use crate::vless::encoding::decode_address;

use super::super::{encoding, new_error, protocol::Address};

#[derive(PartialEq, Debug, Clone)]
pub enum SessionStatus {
    New = 0x01,
    Keep = 0x02,
    End = 0x03,
    KeepAlive = 0x04,
}

#[derive(PartialEq, Debug, Clone)]
pub enum TargetNetwork {
    TCP = 0x01,
    UDP = 0x02,
}

impl fmt::Display for TargetNetwork {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &Self::TCP => write!(f, "tcp"),
            &Self::UDP => write!(f, "udp"),
        }
    }
}

#[derive(PartialEq, Debug, Clone)]
pub struct Destination {
    pub network: TargetNetwork,
    pub address: Address,
}

impl fmt::Display for Destination {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}::{}", self.network, self.address)
    }
}

#[derive(PartialEq, Debug)]
pub struct FrameMetadata {
    pub session_id: u16,
    pub option: u8,
    pub session_status: SessionStatus,
    pub target: Option<Destination>,
}

impl FrameMetadata {
    #[inline]
    pub fn has_data(&self) -> bool {
        FrameOption::Data.is_enable_of(self.option)
    }

    #[inline]
    pub fn has_error(&self) -> bool {
        FrameOption::Error.is_enable_of(self.option)
    }
}

#[derive(Clone, Copy)]
pub enum FrameOption {
    Data = 0x01,
    Error = 0x02,
}

impl FrameOption {
    #[inline]
    pub fn is_enable_of(&self, option: u8) -> bool {
        let flag = self.flag();
        option & flag == flag
    }

    #[inline]
    pub fn flag(&self) -> u8 {
        1 << (*self as u8)
    }

    #[inline]
    pub fn set_to(&self, option: &mut u8) {
        *option &= self.flag()
    }
}

// Frame format
// 2 bytes - length
// 2 bytes - session id
// 1 bytes - status
// 1 bytes - option
//
// 1 byte - network
// 2 bytes - port
// n bytes - address

#[inline]
pub fn encode_frame_serialized_len(frame: &FrameMetadata) -> usize {
    let mut len = 6;

    if frame.session_status == SessionStatus::New {
        if let Some(target) = frame.target.as_ref() {
            len += 1 + encoding::address_serialized_len(&target.address);
        }
    }

    len
}

#[inline]
pub fn encode_frame<W>(w: &mut W, frame: &FrameMetadata) -> io::Result<usize>
where
    W: BufMut + Unpin,
{
    w.put_u16(encode_frame_serialized_len(frame) as u16);
    w.put_u16(frame.session_id);
    w.put_u8(frame.session_status.clone() as u8);
    w.put_u8(frame.option);

    let mut writed = 6;

    if frame.session_status == SessionStatus::New {
        if let Some(target) = frame.target.as_ref() {
            w.put_u8(target.network.clone() as u8);
            writed += 1;

            writed += encoding::encode_address(w, &target.address)?;
        } else {
            return Err(new_error("mux: encode_frame: new sesion no target"));
        }
    }

    Ok(writed)
}

#[inline]
pub fn encode_frame_and_data_len<W>(w: &mut W, frame: &FrameMetadata, data_len: u16) -> io::Result<usize>
where
    W: BufMut + Unpin,
{
    let writed = encode_frame(w, frame)?;
    w.put_u16(data_len);
    Ok(writed)
}

#[inline]
pub async fn decode_frame<R>(stream: &mut R) -> io::Result<FrameMetadata>
where
    R: AsyncRead + Unpin,
{
    let meta_len = stream.read_u16().await? as usize;

    if meta_len > 512 {
        return Err(new_error(format!("mux: ecode_frame: invalid metalen {}", meta_len)));
    }

    let session_id = stream.read_u16().await?;
    let session_status = stream.read_u8().await?;
    let session_status = match session_status {
        0x01 => SessionStatus::New,
        0x02 => SessionStatus::Keep,
        0x03 => SessionStatus::End,
        0x04 => SessionStatus::KeepAlive,
        _ => {
            return Err(new_error(format!(
                "mux: ecode_frame: invalid session_status {}",
                session_status
            )));
        }
    };
    let option = stream.read_u8().await?;

    let mut target = None;

    if session_status == SessionStatus::New {
        let network = stream.read_u8().await?;
        let network = match network {
            0x01 => TargetNetwork::TCP,
            0x02 => TargetNetwork::UDP,
            _ => {
                return Err(new_error(format!("mux: ecode_frame: invalid network {}", network)));
            }
        };

        let address = decode_address(stream).await?;

        target = Some(Destination { network, address });
    }

    Ok(FrameMetadata {
        session_id,
        option,
        session_status,
        target,
    })
}

#[cfg(test)]
mod test {
    use super::*;
    use std::{assert_matches::assert_matches, io::Cursor};

    #[tokio::test]
    async fn test_rebuild_domain() {
        let origin_frame = FrameMetadata {
            session_id: 2,
            option: 0,
            session_status: SessionStatus::New,
            target: Some(Destination {
                network: TargetNetwork::UDP,
                address: Address::DomainNameAddress("www.v2fly.org".to_string(), 443),
            }),
        };

        let mut buffer = Vec::new();
        assert_matches!(encode_frame(&mut buffer, &origin_frame), Ok(24));

        let r = decode_frame(&mut Cursor::new(&mut buffer[..])).await;
        assert_matches!(r, Ok(..));
        assert_eq!(r.unwrap(), origin_frame);
    }
}
