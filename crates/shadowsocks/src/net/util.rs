use std::io;
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener};

pub fn generate_port() -> io::Result<u16> {
    let loopback = Ipv4Addr::new(127, 0, 0, 1);
    let socket = SocketAddrV4::new(loopback, 0);
    let listener = TcpListener::bind(socket)?;
    let addr = listener.local_addr()?;
    Ok(addr.port())
}
