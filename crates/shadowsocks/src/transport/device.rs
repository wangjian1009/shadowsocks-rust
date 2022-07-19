pub trait DeviceGuard {
    fn device(&self) -> DeviceOrGuard<'_>;
}

pub trait PrivateDevice {
    fn local_addr(&self) -> std::io::Result<std::net::SocketAddr>;
}

#[derive(Clone)]
pub enum Device<'a> {
    Tcp(&'a tokio::net::TcpStream),
    Udp(&'a tokio::net::UdpSocket),
    TofTcp(&'a tokio_tfo::TfoStream),
    Private(&'a dyn PrivateDevice),
}

pub enum DeviceOrGuard<'a> {
    Device(Device<'a>),
    Guard(Box<dyn DeviceGuard + 'a>),
}

impl DeviceOrGuard<'_> {
    pub fn apply<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&Device<'_>) -> R,
    {
        match self {
            Self::Device(device) => f(device),
            Self::Guard(guard) => {
                let inner = guard.device();
                inner.apply(f)
            }
        }
    }
}
