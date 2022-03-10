use super::{super::common::UUID, Address};

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum RequestCommand {
    TCP = 0x01,
    UDP = 0x02,
    Mux = 0x03,
}

#[derive(Debug, PartialEq)]
pub struct RequestHeader {
    pub version: u8,
    pub command: RequestCommand,
    pub address: Option<Address>,
    pub user: UUID,
}
