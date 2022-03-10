use super::*;
use async_trait::async_trait;
use bytes::BufMut;
use mockall::*;

use crate::transport::{PacketMutWrite, PacketRead, PacketWrite};

mock! {
    pub PacketWrite {}

    #[async_trait]
    impl PacketWrite for PacketWrite {
        async fn write_to(&self, buf: &[u8], addr: &ServerAddr) -> io::Result<()>;
    }

    #[async_trait]
    impl PacketMutWrite for PacketWrite {
        async fn write_to_mut(&mut self, buf: &[u8], addr: &ServerAddr) -> io::Result<()>;
    }
}

mock! {
    pub PacketRead {}

    #[async_trait]
    impl PacketRead for PacketRead {
        async fn read_from(&mut self, buf: &mut [u8]) -> io::Result<(usize, ServerAddr)>;
    }
}

impl MockPacketRead {
    pub fn read_one_block(&mut self, input: Vec<u8>, addr: &str) {
        let addr = addr.parse::<ServerAddr>().unwrap();
        self.expect_read_from().times(1).returning(move |mut buf: &mut [u8]| {
            buf.put_slice(&input[..]);
            Ok((input.len(), addr.clone()))
        });
    }
}
