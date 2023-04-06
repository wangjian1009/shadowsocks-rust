use std::net::SocketAddr;

pub trait Endpoint: Sync + Send + 'static {
    fn from_address(addr: SocketAddr) -> Self;
    fn into_address(&self) -> SocketAddr;
    fn clear_src(&mut self);
}
