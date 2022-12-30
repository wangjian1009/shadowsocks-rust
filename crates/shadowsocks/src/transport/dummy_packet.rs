use super::{PacketMutWrite, PacketRead};
use crate::ServerAddr;
use async_trait::async_trait;
use std::{io, net::SocketAddr};

pub struct DummyPacket {}

#[async_trait]
impl PacketRead for DummyPacket {
    async fn read_from(&mut self, _: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        unimplemented!()
    }
}

#[async_trait]
impl PacketMutWrite for DummyPacket {
    async fn write_to_mut(&mut self, _: &[u8], _: &ServerAddr) -> io::Result<()> {
        unimplemented!()
    }
}
