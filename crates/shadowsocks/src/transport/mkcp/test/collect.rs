use super::*;
use async_trait::async_trait;
// use std::net::SocketAddr;

use super::segment::*;
use crate::transport::{PacketMutWrite, PacketWrite};

use super::mock::MockPacketRead;
use tokio::sync::mpsc;

pub struct PacketCollector {
    _sender: mpsc::Sender<Segment>,
}

#[async_trait]
impl PacketWrite for PacketCollector {
    async fn write_to(&self, buf: &[u8], addr: &ServerAddr) -> io::Result<()> {
        let mut pr = MockPacketRead::new();
        pr.read_one_block(buf.to_vec(), addr.to_string().as_str());
        let mut pr = MkcpPacketReader::new(pr, None, None);
        let (segments, ..) = pr.read().await?;

        for seg in segments {
            match self.sender.send(seg).await {
                Ok(()) => {}
                Err(err) => panic!("send seg error: {}", err),
            }
        }

        Ok(())
    }
}

#[async_trait]
impl PacketMutWrite for PacketCollector {
    async fn write_to_mut(&mut self, buf: &[u8], addr: &ServerAddr) -> io::Result<()> {
        self.write_to(buf, addr).await
    }
}

pub fn create_connection(
    _config: Arc<MkcpConfig>,
    _conv: u16,
    _way: MkcpConnWay,
    _local_addr: &str,
    _remote_addr: &str,
    _statistic: Option<Arc<StatisticStat>>,
) -> (MkcpConnection, mpsc::Receiver<Segment>) {
    // let (tx, rx) = mpsc::channel(100);

    // let pw = PacketCollector { sender: tx };

    // (
    //     MkcpConnection::new(
    //         config,
    //         MkcpConnMetadata {
    //             way,
    //             local_addr: local_addr.parse::<SocketAddr>().unwrap(),
    //             remote_addr: remote_addr.parse::<ServerAddr>().unwrap(),
    //             conversation: conv,
    //         },
    //         None,
    //         Arc::new(MkcpPacketWriter::new(pw, None, None)),
    //         statistic,
    //     ),
    //     rx,
    // )
}

pub fn create_connection_ctx(
    _config: Arc<MkcpConfig>,
    _conv: u16,
    _way: MkcpConnWay,
    _local_addr: &str,
    _remote_addr: &str,
    _statistic: Option<Arc<StatisticStat>>,
) -> (connection::MkcpConnectionContext, mpsc::Receiver<Segment>) {
    // let (tx, rx) = mpsc::channel(100);

    // let pw = PacketCollector { sender: tx };

    // let (ctx, _data_updator, _ping_updator) = connection::MkcpConnectionContext::new(
    //     config,
    //     MkcpConnMetadata {
    //         way,
    //         local_addr: local_addr.parse::<SocketAddr>().unwrap(),
    //         remote_addr: remote_addr.parse::<ServerAddr>().unwrap(),
    //         conversation: conv,
    //     },
    //     None,
    //     Arc::new(MkcpPacketWriter::new(pw, None, None)),
    //     statistic,
    // );

    // (ctx, rx)
    unimplemented!()
}
