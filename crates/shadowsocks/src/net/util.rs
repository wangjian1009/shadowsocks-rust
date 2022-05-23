use std::io;
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener};

pub fn generate_port() -> io::Result<u16> {
    let loopback = Ipv4Addr::new(127, 0, 0, 1);
    let socket = SocketAddrV4::new(loopback, 0);
    let listener = TcpListener::bind(socket)?;
    let addr = listener.local_addr()?;
    Ok(addr.port())
}

#[cfg(unix)]
pub fn check_peekable<F: std::os::unix::io::AsRawFd>(fd: &F) -> bool {
    let fd = fd.as_raw_fd();

    unsafe {
        let mut peek_buf = [0u8; 1];

        let ret = libc::recv(
            fd,
            peek_buf.as_mut_ptr() as *mut libc::c_void,
            peek_buf.len(),
            libc::MSG_PEEK | libc::MSG_DONTWAIT,
        );

        match ret.cmp(&0) {
            // EOF, connection lost
            std::cmp::Ordering::Equal => false,
            // Data in buffer
            std::cmp::Ordering::Greater => true,
            std::cmp::Ordering::Less => {
                let err = io::Error::last_os_error();
                // EAGAIN, EWOULDBLOCK
                // Still connected.
                err.kind() == io::ErrorKind::WouldBlock
            }
        }
    }
}

#[cfg(windows)]
pub fn check_peekable<F: std::os::windows::io::AsRawSocket>(s: &mut F) -> bool {
    use windows_sys::{
        core::PSTR,
        Win32::Networking::WinSock::{recv, MSG_PEEK, SOCKET},
    };

    let sock = s.as_raw_socket() as SOCKET;

    unsafe {
        let mut peek_buf = [0u8; 1];

        let ret = recv(sock, peek_buf.as_mut_ptr() as PSTR, peek_buf.len() as i32, MSG_PEEK);

        match ret.cmp(&0) {
            // EOF, connection lost
            std::cmp::Ordering::Equal => false,
            // Data in buffer
            std::cmp::Ordering::Greater => true,
            std::cmp::Ordering::Less => {
                let err = io::Error::last_os_error();
                // I have to trust the `s` have already set to non-blocking mode
                // Because windows doesn't have MSG_DONTWAIT
                err.kind() == io::ErrorKind::WouldBlock
            }
        }
    }
}
