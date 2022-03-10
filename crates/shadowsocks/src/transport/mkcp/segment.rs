use bytes::{BufMut, Bytes};
use std::{
    fmt::{self, Debug},
    io,
    sync::Arc,
};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::new_error;

pub const ACK_NUMBER_LIMIT: usize = 128;
pub const DATA_SEGMENT_OVERHEAD: u8 = 18;

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Command {
    Ack = 0,       // CommandACK indicates an AckSegment.
    Data = 1,      // CommandData indicates a DataSegment.
    Terminate = 2, // CommandTerminate indicates that peer terminates the connection.
    Ping = 3,      // CommandPing indicates a ping.
}

#[derive(Clone, Copy)]
pub enum SegmentOption {
    Close = 1,
}

impl SegmentOption {
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

#[derive(PartialEq, Debug, Clone)]
pub struct DataSegment {
    pub timestamp: u32,
    pub number: u32,
    pub sending_next: u32,
    pub payload: Arc<Bytes>,
}

impl DataSegment {
    #[inline]
    pub fn byte_size(&self) -> usize {
        4 + 4 + 4 + 2 + self.payload.len()
    }

    #[inline]
    pub fn write_to_buf<B: BufMut>(&self, cursor: &mut B) {
        cursor.put_u32(self.timestamp);
        cursor.put_u32(self.number);
        cursor.put_u32(self.sending_next);
        cursor.put_u16(self.payload.len() as u16);
        cursor.put_slice(self.payload.as_ref());
    }

    pub async fn read_from<R>(stream: &mut R) -> io::Result<Self>
    where
        R: AsyncRead + Unpin,
    {
        let timestamp = stream.read_u32().await?;
        let number = stream.read_u32().await?;
        let sending_next = stream.read_u32().await?;

        let len = stream.read_u16().await? as usize;

        let mut buf = vec![0; len];
        if len > 0 {
            stream.read_exact(&mut buf).await?;
        }
        let payload = Arc::new(Bytes::from(buf));

        Ok(Self {
            timestamp,
            number,
            sending_next,
            payload,
        })
    }
}

#[derive(PartialEq, Debug)]
pub struct AckSegment {
    pub receiving_window: u32,
    pub receiving_next: u32,
    pub timestamp: u32,
    pub number_list: Vec<u32>,
}

impl AckSegment {
    #[inline]
    pub fn new() -> Self {
        Self {
            receiving_window: 0,
            receiving_next: 0,
            timestamp: 0,
            number_list: vec![],
        }
    }

    #[inline]
    pub fn put_timestamp(&mut self, timestamp: u32) {
        if timestamp.wrapping_sub(self.timestamp) < 0x7FFFFFFF {
            self.timestamp = timestamp
        }
    }

    #[inline]
    pub fn put_number(&mut self, number: u32) {
        self.number_list.push(number);
    }

    #[inline]
    pub fn is_full(&self) -> bool {
        self.number_list.len() == ACK_NUMBER_LIMIT as usize
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.number_list.len() == 0
    }

    #[inline]
    pub fn byte_size(&self) -> usize {
        return 4 + 4 + 4 + 1 + (self.number_list.len() * 4);
    }

    #[inline]
    pub fn write_to_buf<B: BufMut>(&self, cursor: &mut B) {
        cursor.put_u32(self.receiving_window);
        cursor.put_u32(self.receiving_next);
        cursor.put_u32(self.timestamp);
        cursor.put_u8(self.number_list.len() as u8);
        for number in self.number_list.iter() {
            cursor.put_u32(number.clone());
        }
    }

    pub async fn read_from<R>(stream: &mut R) -> io::Result<Self>
    where
        R: AsyncRead + Unpin,
    {
        let receiving_window = stream.read_u32().await?;
        let receiving_next = stream.read_u32().await?;
        let timestamp = stream.read_u32().await?;
        let len = stream.read_u8().await? as usize;

        let mut number_list = Vec::with_capacity(len);
        for _ in 0..len {
            number_list.push(stream.read_u32().await?);
        }

        Ok(Self {
            receiving_window,
            receiving_next,
            timestamp,
            number_list,
        })
    }
}

#[derive(PartialEq, Debug)]
pub struct CmdOnlySegment {
    pub cmd: Command,
    pub sending_next: u32,
    pub receiving_next: u32,
    pub peer_rto: u32,
}

impl CmdOnlySegment {
    #[inline]
    pub fn byte_size(&self) -> usize {
        4 + 4 + 4
    }

    #[inline]
    pub fn write_to_buf<B: BufMut>(&self, cursor: &mut B) {
        cursor.put_u32(self.sending_next);
        cursor.put_u32(self.receiving_next);
        cursor.put_u32(self.peer_rto);
    }

    pub async fn read_from<R>(cmd: Command, stream: &mut R) -> io::Result<Self>
    where
        R: AsyncRead + Unpin,
    {
        let sending_next = stream.read_u32().await?;
        let receiving_next = stream.read_u32().await?;
        let peer_rto = stream.read_u32().await?;

        Ok(Self {
            cmd,
            sending_next,
            receiving_next,
            peer_rto,
        })
    }
}

#[derive(PartialEq, Debug)]
pub enum SegmentData {
    Ack(AckSegment),
    Data(DataSegment),
    CmdOnlySegment(CmdOnlySegment),
}

#[derive(PartialEq)]
pub struct Segment {
    pub conv: u16,
    pub option: u8,
    pub data: SegmentData,
}

impl Debug for Segment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: (", self.conv)?;

        if SegmentOption::Close.is_enable_of(self.option) {
            write!(f, "close")?;
        }

        write!(f, ") ")?;

        match &self.data {
            SegmentData::Ack(data) => {
                write!(
                    f,
                    "ack: receiving-window={}, receiving-next={}, members={:?}, timestamp={}",
                    data.receiving_window, data.receiving_next, data.number_list, data.timestamp,
                )?;
            }
            SegmentData::Data(data) => {
                write!(
                    f,
                    "data: number={}, sending-next={}, payload={}, timestamp={}",
                    data.number,
                    data.sending_next,
                    data.payload.len(),
                    data.timestamp,
                )?;
            }
            SegmentData::CmdOnlySegment(data) => {
                match data.cmd {
                    Command::Ping => write!(f, "ping: ")?,
                    Command::Terminate => write!(f, "terminate: ")?,
                    _ => unreachable!(),
                };

                write!(
                    f,
                    "sending-next={}, receiving-next={}, peer-rto={}",
                    data.sending_next, data.receiving_next, data.peer_rto
                )?
            }
        }

        Ok(())
    }
}

impl Segment {
    #[inline]
    pub fn cmd(&self) -> Command {
        match &self.data {
            SegmentData::Ack(..) => Command::Ack,
            SegmentData::Data(..) => Command::Data,
            SegmentData::CmdOnlySegment(data) => data.cmd,
        }
    }

    #[inline]
    pub fn byte_size(&self) -> usize {
        2 + 1
            + 1
            + match &self.data {
                SegmentData::Ack(seg) => seg.byte_size(),
                SegmentData::Data(seg) => seg.byte_size(),
                SegmentData::CmdOnlySegment(seg) => seg.byte_size(),
            }
    }

    #[inline]
    pub fn write_to_buf<B: BufMut>(&self, cursor: &mut B) {
        cursor.put_u16(self.conv);
        cursor.put_u8(self.cmd() as u8);
        cursor.put_u8(self.option);

        match &self.data {
            SegmentData::Ack(seg) => seg.write_to_buf(cursor),
            SegmentData::Data(seg) => seg.write_to_buf(cursor),
            SegmentData::CmdOnlySegment(seg) => seg.write_to_buf(cursor),
        }
    }

    pub async fn read_from<R>(stream: &mut R) -> io::Result<Self>
    where
        R: AsyncRead + Unpin,
    {
        let conv = stream.read_u16().await?;
        let cmd = stream.read_u8().await?;
        let option = stream.read_u8().await?;

        let data = if cmd == (Command::Ack as u8) {
            SegmentData::Ack(AckSegment::read_from(stream).await?)
        } else if cmd == (Command::Data as u8) {
            SegmentData::Data(DataSegment::read_from(stream).await?)
        } else if cmd == (Command::Terminate as u8) {
            SegmentData::CmdOnlySegment(CmdOnlySegment::read_from(Command::Terminate, stream).await?)
        } else if cmd == (Command::Ping as u8) {
            SegmentData::CmdOnlySegment(CmdOnlySegment::read_from(Command::Ping, stream).await?)
        } else {
            return Err(new_error(format!("Segment::read_from: not support cmd {}", cmd)));
        };

        Ok(Segment { conv, option, data })
    }

    pub async fn write_to<W>(&self, w: &mut W) -> io::Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        let mut buf = Vec::with_capacity(self.byte_size());
        let cursor = &mut buf;
        self.write_to_buf(cursor);
        w.write(&buf).await?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use bytes::Bytes;
    use std::io::Cursor;

    #[tokio::test]
    async fn bad_segment() {
        let r = Segment::read_from(&mut Cursor::new([])).await;
        assert_eq!(format!("{:?}", r), "Err(Kind(UnexpectedEof))".to_owned());
    }

    #[tokio::test]
    async fn data_segment() {
        let seg = Segment {
            conv: 1,
            option: 0,
            data: SegmentData::Data(DataSegment {
                timestamp: 3,
                number: 4,
                sending_next: 5,
                payload: Arc::new(Bytes::from_static(b"abcd")),
            }),
        };

        let mut buf: Vec<u8> = Vec::with_capacity(seg.byte_size());
        seg.write_to_buf(&mut buf);

        let iseg = Segment::read_from(&mut Cursor::new(buf.as_mut_slice())).await.unwrap();
        assert_eq!(seg, iseg);
    }

    #[tokio::test]
    async fn data_segment_1byte() {
        let seg = Segment {
            conv: 1,
            option: 0,
            data: SegmentData::Data(DataSegment {
                timestamp: 3,
                number: 4,
                sending_next: 5,
                payload: Arc::new(Bytes::from_static(b"a")),
            }),
        };

        let mut buf: Vec<u8> = Vec::with_capacity(seg.byte_size());
        seg.write_to_buf(&mut buf);

        let iseg = Segment::read_from(&mut Cursor::new(buf.as_mut_slice())).await.unwrap();
        assert_eq!(seg, iseg);
    }

    #[tokio::test]
    async fn ack_segment() {
        let _ = env_logger::builder()
            .filter_level(log::LevelFilter::Debug)
            .is_test(true)
            .try_init();

        let seg = Segment {
            conv: 1,
            option: 0,
            data: SegmentData::Ack(AckSegment {
                receiving_window: 2,
                receiving_next: 3,
                timestamp: 10,
                number_list: vec![1, 3, 5, 7, 9],
            }),
        };

        let mut buf: Vec<u8> = Vec::with_capacity(seg.byte_size());
        seg.write_to_buf(&mut buf);

        let iseg = Segment::read_from(&mut Cursor::new(buf.as_mut_slice())).await.unwrap();
        assert_eq!(seg, iseg);
    }

    #[tokio::test]
    async fn cmd_segment() {
        let seg = Segment {
            conv: 1,
            option: SegmentOption::Close.flag(),
            data: SegmentData::CmdOnlySegment(CmdOnlySegment {
                cmd: Command::Ping,
                sending_next: 11,
                receiving_next: 13,
                peer_rto: 15,
            }),
        };

        let mut buf: Vec<u8> = Vec::with_capacity(seg.byte_size());
        seg.write_to_buf(&mut buf);

        let iseg = Segment::read_from(&mut Cursor::new(buf.as_mut_slice())).await.unwrap();
        assert_eq!(seg, iseg);
    }
}
