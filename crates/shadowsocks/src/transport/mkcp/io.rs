use std::{
    io::{self, Cursor},
    sync::Arc,
};

use bytes::BufMut;
use rand::RngCore;

use crate::{relay::udprelay::MAXIMUM_UDP_PAYLOAD_SIZE, ServerAddr};

use super::{
    super::{PacketRead, PacketWrite},
    new_error,
    segment::Segment,
    HeaderPolicy,
    Security,
};

pub struct MkcpPacketReader<PR: PacketRead> {
    header: Option<Arc<HeaderPolicy>>,
    security: Option<Arc<Security>>,
    inner: PR,
}

impl<PR: PacketRead> MkcpPacketReader<PR> {
    pub fn new(inner: PR, header: Option<Arc<HeaderPolicy>>, security: Option<Arc<Security>>) -> Self {
        Self {
            header,
            security,
            inner,
        }
    }

    pub async fn read(&mut self) -> io::Result<(Vec<Segment>, ServerAddr)> {
        let mut buffer = [0u8; MAXIMUM_UDP_PAYLOAD_SIZE];
        let (size, addr) = self.inner.read_from(&mut buffer).await?;

        let mut b: &mut [u8] = &mut buffer[..size];

        if let Some(header) = self.header.as_ref() {
            if b.len() <= header.size() {
                return Err(new_error(format!(
                    "read packet: not enough input, header-size={}, input={}",
                    header.size(),
                    b.len()
                )));
            }
            b = &mut b[header.size()..];
        }

        if let Some(security) = self.security.as_ref() {
            let nonce_size = security.nonce_size();
            if b.len() <= nonce_size {
                return Err(new_error("read packet: not enough input"));
            }

            let (nonce, data) = b.split_at_mut(nonce_size);
            let plen = security.open(nonce, data, None)?;
            b = &mut data[..plen];
        }

        let plen = b.len();
        let mut cursor = Cursor::new(b);
        let mut segments = Vec::new();
        while cursor.position() < plen as u64 {
            let segment = Segment::read_from(&mut cursor).await?;
            segments.push(segment);
        }

        Ok((segments, addr))
    }
}

pub struct MkcpPacketWriter<PW: PacketWrite> {
    header: Option<Arc<HeaderPolicy>>,
    security: Option<Arc<Security>>,
    inner: PW,
}

impl<PW: PacketWrite> MkcpPacketWriter<PW> {
    pub fn new(inner: PW, header: Option<Arc<HeaderPolicy>>, security: Option<Arc<Security>>) -> Self {
        Self {
            header,
            inner,
            security,
        }
    }

    pub fn overhead(&self) -> usize {
        let mut overhead = 0;

        if let Some(header) = self.header.as_ref() {
            overhead += header.size();
        }

        if let Some(security) = self.security.as_ref() {
            overhead += security.nonce_size() + security.overhead();
        }

        overhead
    }

    pub async fn write(&self, remote_addr: &ServerAddr, seg: &Segment) -> io::Result<()> {
        let mut buffer = [0u8; MAXIMUM_UDP_PAYLOAD_SIZE];

        // 计算大小
        let seg_size = seg.byte_size();
        let overhead_size = self.overhead();

        let total_size = seg_size + overhead_size;
        if total_size > buffer.len() {
            return Err(new_error(format!(
                "write packet: not enough buf for nonce, overhead-size={}, seg-size={}, capacity={}",
                seg_size,
                overhead_size,
                buffer.len()
            )));
        }

        // 构造输出
        let mut b: &mut [u8] = &mut buffer;
        let mut output_len = 0;

        if let Some(header) = self.header.as_ref() {
            header.serialize(&mut b[..header.size()]);
            b = &mut b[header.size()..];
            output_len += header.size();
        }

        if let Some(security) = self.security.as_ref() {
            let nonce_size = security.nonce_size();
            if nonce_size > b.len() {
                return Err(new_error(format!(
                    "write packet: not enough buf for nonce, nonce-size={}",
                    nonce_size,
                )));
            }

            let mut nonce = vec![0u8; nonce_size];
            if nonce_size > 0 {
                let mut rng = rand::thread_rng();
                loop {
                    rng.fill_bytes(&mut nonce);
                    let is_zeros = nonce.iter().all(|&x| x == 0);
                    if !is_zeros {
                        break;
                    }
                }
                b.put_slice(&nonce);
                output_len += nonce_size;
            }

            let mut cursor = &mut b[..seg_size];
            seg.write_to_buf(&mut cursor);
            let cipher_len = security.seal(&nonce, &mut b[..], seg_size, None)?;
            output_len += cipher_len;
        } else {
            seg.write_to(&mut Cursor::new(b)).await?;
            output_len += seg_size;
        }

        self.inner.write_to(&buffer[..output_len], remote_addr).await?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::{
        super::{
            crypt::SimpleAuthenticator,
            cryptreal::AEADAESGCMBasedOnSeed,
            header::wechat::VideoChat,
            segment::{AckSegment, DataSegment, SegmentData},
            test::mock::{MockPacketRead, MockPacketWrite},
        },
        *,
    };
    use bytes::Bytes;

    async fn packet_read(
        input: &[u8],
        header: Option<Arc<HeaderPolicy>>,
        security: Option<Arc<Security>>,
    ) -> io::Result<Vec<Segment>> {
        let mut pr = MockPacketRead::new();
        pr.read_one_block(input.to_vec(), "1.1.1.1:80");

        let mut reader = MkcpPacketReader::new(pr, header, security);

        let (segments, addr) = reader.read().await?;
        assert_eq!(addr.to_string(), "1.1.1.1:80");
        Ok(segments)
    }

    async fn packet_write(
        seg: &Segment,
        header: Option<Arc<HeaderPolicy>>,
        security: Option<Arc<Security>>,
    ) -> io::Result<Vec<u8>> {
        let addr = "1.1.1.1:80".parse::<ServerAddr>().unwrap();

        let output_buf = Arc::new(spin::Mutex::new(Vec::<u8>::new()));

        let mut pw = MockPacketWrite::new();
        let output_buf_dup = output_buf.clone();
        pw.expect_write_to()
            .times(1)
            .returning(move |buf: &[u8], addr: &ServerAddr| {
                assert_eq!(addr.to_string(), "1.1.1.1:80".to_string());
                output_buf_dup.lock().put_slice(buf);
                Ok(())
            });

        let writer = MkcpPacketWriter::new(pw, header, security);

        writer.write(&addr, seg).await?;

        let result = output_buf.lock().clone();
        Ok(result)
    }

    async fn segment_rebuild(
        seg: &Segment,
        header: Option<Arc<HeaderPolicy>>,
        security: Option<Arc<Security>>,
    ) -> io::Result<Segment> {
        let buf = packet_write(seg, header.clone(), security.clone()).await?;
        let mut segs = packet_read(&buf, header, security).await?;
        assert_eq!(segs.len(), 1);
        Ok(segs.remove(0))
    }

    #[tokio::test]
    async fn packet_reader_empty() {
        let segments = packet_read(&[], None, None).await.unwrap();
        assert_eq!(segments, vec![]);
    }

    #[tokio::test]
    async fn packet_reader_1_byte() {
        assert_eq!(
            "Err(Kind(UnexpectedEof))",
            format!("{:?}", packet_read(&[1], None, None).await)
        );
    }

    #[tokio::test]
    async fn packet_rebuild_ack() {
        let seg = Segment {
            conv: 1,
            option: 2,
            data: SegmentData::Ack(AckSegment {
                receiving_window: 10,
                receiving_next: 11,
                timestamp: 12,
                number_list: vec![1, 2],
            }),
        };

        let seg2 = segment_rebuild(&seg, None, None).await.unwrap();
        assert_eq!(seg, seg2);
    }

    #[tokio::test]
    async fn packet_rebuild_data() {
        let seg = Segment {
            conv: 1,
            option: 2,
            data: SegmentData::Data(DataSegment {
                timestamp: 1000,
                number: 1004,
                sending_next: 1002,
                payload: Arc::new(Bytes::from_static(b"abdcd")),
            }),
        };

        let seg2 = segment_rebuild(&seg, None, None).await.unwrap();
        assert_eq!(seg, seg2);
    }

    #[tokio::test]
    async fn packet_rebuild_weixin_simple() {
        let seg = Segment {
            conv: 1,
            option: 2,
            data: SegmentData::Ack(AckSegment {
                receiving_window: 10,
                receiving_next: 11,
                timestamp: 12,
                number_list: vec![1, 2],
            }),
        };

        let seg2 = segment_rebuild(
            &seg,
            Some(Arc::new(Box::new(VideoChat::new()) as HeaderPolicy)),
            Some(Arc::new(Box::new(SimpleAuthenticator::new()) as Security)),
        )
        .await
        .unwrap();
        assert_eq!(seg, seg2);
    }

    #[tokio::test]
    async fn packet_rebuild_simple() {
        let _ = env_logger::builder()
            .filter_level(log::LevelFilter::Debug)
            .is_test(true)
            .try_init();

        let seg = Segment {
            conv: 1,
            option: 2,
            data: SegmentData::Ack(AckSegment {
                receiving_window: 10,
                receiving_next: 11,
                timestamp: 12,
                number_list: vec![1, 2],
            }),
        };

        let seg2 = segment_rebuild(
            &seg,
            None,
            Some(Arc::new(Box::new(SimpleAuthenticator::new()) as Security)),
        )
        .await
        .unwrap();
        assert_eq!(seg, seg2);
    }

    #[tokio::test]
    async fn packet_rebuild_weixin_real() {
        let _ = env_logger::builder()
            .filter_level(log::LevelFilter::Debug)
            .is_test(true)
            .try_init();

        let seg = Segment {
            conv: 1,
            option: 2,
            data: SegmentData::Ack(AckSegment {
                receiving_window: 10,
                receiving_next: 11,
                timestamp: 12,
                number_list: vec![1, 2],
            }),
        };

        let seg2 = segment_rebuild(
            &seg,
            Some(Arc::new(Box::new(VideoChat::new()) as HeaderPolicy)),
            Some(Arc::new(Box::new(AEADAESGCMBasedOnSeed::new("itest123")) as Security)),
        )
        .await
        .unwrap();
        assert_eq!(seg, seg2);
    }
}
