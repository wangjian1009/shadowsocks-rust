use std::{fmt, os::unix::fs::FileTypeExt};
use tokio::fs;

pub async fn dump_fd_info(prefix: Option<&str>) {
    let prefix = match prefix {
        Some(prefix) => format!("{}: ", prefix),
        None => "".into(),
    };
    
    match load_fd_info().await {
        Ok(fd_info) => {
            for info in fd_info {
                let fd = info.fd;
                match info.info {
                    Ok((type_str, link)) => {
                        tracing::info!("{prefix}{fd}: {type_str} {link}");
                    }
                    Err(err) => {
                        tracing::info!("{prefix}{fd}: {err}");
                    }
                }
            }
        }
        Err(err) => {
            tracing::info!("{prefix}load fd info error: {err}");
            return;
        }
    };
}

pub struct FdInfo {
    pub fd: i32,
    pub info: Result<(String, String), String>,
}

impl fmt::Display for FdInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.info {
            Ok((type_str, link)) => write!(f, "{}: {} {}", self.fd, type_str, link),
            Err(err) => write!(f, "{}: {}", self.fd, err),
        }
    }
}

pub async fn load_fd_info() -> Result<Vec<FdInfo>, String> {
    let mut result = Vec::new();

    let mut entries = fs::read_dir("/proc/self/fd")
        .await
        .map_err(|err| format!("open dir /proc/self/fd faild, err: {}", err))?;

    while let Some(entry) = entries
        .next_entry()
        .await
        .map_err(|err| format!("read dir entry failed, err: {}", err))?
    {
        let fd_path = entry.path();

        let fd = match fd_path.file_name() {
            Some(s) => match s.to_str() {
                Some(s) => match s.parse::<i32>() {
                    Ok(fd) => fd,
                    Err(err) => {
                        tracing::error!(path=?fd_path, err=?err, "read fd: invalid file name");
                        continue;
                    }
                },
                None => {
                    tracing::error!(path=?fd_path, "read fd: invalid file name");
                    continue;
                }
            },
            None => {
                tracing::error!(path=?fd_path, "read fd: no file name");
                continue;
            }
        };

        let metadata = match fs::metadata(&fd_path).await {
            Ok(metadata) => metadata,
            Err(err) => {
                result.push(FdInfo {
                    fd,
                    info: Err(format!("read metadata error: {:?}", err)),
                });
                continue;
            }
        };

        let file_type = metadata.file_type();

        let link = match fs::read_link(&fd_path).await {
            Ok(link) => link,
            Err(err) => {
                result.push(FdInfo {
                    fd,
                    info: Err(format!("read link error: {:?}", err)),
                });
                continue;
            }
        };

        if file_type.is_socket() {
            let mut sock_info = format!("{} ", link.display());

            let (local_addr, local_addr_len) = match get_sock_local_addr(fd) {
                Ok(s) => s,
                Err(err) => {
                    result.push(FdInfo {
                        fd,
                        info: Err(format!("getsockname error: {}", err)),
                    });
                    continue;
                }
            };

            // 对于 AF_INET 和 AF_INET6 的 socket，获取 socket 类型
            if local_addr.ss_family == libc::AF_INET as libc::sa_family_t
                || local_addr.ss_family == libc::AF_INET6 as libc::sa_family_t
            {
                let sock_type = match get_sock_type(fd) {
                    Ok(s) => s,
                    Err(err) => {
                        result.push(FdInfo {
                            fd,
                            info: Err(format!("get_sock_type error: {}", err)),
                        });
                        continue;
                    }
                };
                sock_info.push_str(format!("{} ", sock_type).as_str());
            }

            if local_addr.ss_family == libc::AF_INET as libc::sa_family_t {
                sock_info.push_str("IPV4 ");
            } else if local_addr.ss_family == libc::AF_INET6 as libc::sa_family_t {
                sock_info.push_str("IPV6 ");
            } else if local_addr.ss_family == libc::AF_UNIX as libc::sa_family_t {
                sock_info.push_str("UNIX ");
            } else {
                sock_info.push_str(&format!("unknown protocol {} ", local_addr.ss_family));
                continue;
            }
            sock_info.push_str(&sockaddr_storage_to_socket_addr(&local_addr, local_addr_len));

            match get_sock_peer_addr(fd) {
                Ok(Some((addr, addr_len))) => {
                    sock_info.push_str(" -- ");
                    sock_info.push_str(&sockaddr_storage_to_socket_addr(&addr, addr_len));
                },
                Ok(None) => {
                    continue;
                }
                Err(err) => {
                    sock_info.push_str(" -- ");
                    sock_info.push_str(err.as_str());
                    continue;
                }
            }

            result.push(FdInfo {
                fd,
                info: Ok(("SOCK".to_owned(), sock_info)),
            });
        } else {
            let type_str = if file_type.is_symlink() {
                "LNK".to_owned()
            } else if file_type.is_file() {
                "REG".to_owned()
            } else if file_type.is_dir() {
                "DIR".to_owned()
            } else if file_type.is_char_device() {
                "CHR".to_owned()
            } else if file_type.is_block_device() {
                "BLK".to_owned()
            } else if file_type.is_fifo() {
                "FIFO".to_owned()
            } else {
                format!("{:?}", file_type)
            };

            result.push(FdInfo {
                fd,
                info: Ok((type_str, format!("{}", link.display()))),
            });
        }
    }

    Ok(result)
}

fn get_sock_local_addr(fd: i32) -> Result<(libc::sockaddr_storage, libc::socklen_t), String> {
    let mut local_addr: libc::sockaddr_storage = unsafe { ::std::mem::zeroed() };
    let mut local_addr_len = std::mem::size_of_val(&local_addr) as libc::socklen_t;
    let ret = unsafe {
        libc::getsockname(
            fd as libc::c_int,
            &mut local_addr as *mut _ as *mut libc::sockaddr,
            &mut local_addr_len,
        )
    };
    if ret != 0 {
        return Err(format!("getsockname error: {}", tokio::io::Error::last_os_error()));
    }
    Ok((local_addr, local_addr_len))
}

fn get_sock_peer_addr(fd: i32) -> Result<Option<(libc::sockaddr_storage, libc::socklen_t)>, String> {
    let mut peer_addr: libc::sockaddr_storage = unsafe { ::std::mem::zeroed() };
    let mut peer_addr_len = std::mem::size_of_val(&peer_addr) as libc::socklen_t;
    let ret = unsafe {
        libc::getpeername(
            fd as libc::c_int,
            &mut peer_addr as *mut _ as *mut libc::sockaddr,
            &mut peer_addr_len,
        )
    };

    if ret != 0 {
        let err = tokio::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ENOTCONN) {
            return Ok(None);
        } else {
            Err(format!("getpeername error: {}", err))
        }
    } else {
        Ok(Some((peer_addr, peer_addr_len)))
    }
}

fn get_sock_type(fd: i32) -> Result<String, String> {
    let mut so_type: libc::c_int = 0;
    let mut so_type_len = std::mem::size_of_val(&so_type) as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            fd as libc::c_int,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            &mut so_type as *mut _ as *mut libc::c_void,
            &mut so_type_len,
        )
    };

    if ret != 0 {
        return Err(format!("getsockopt error: {}", tokio::io::Error::last_os_error()));
    }

    if so_type == libc::SOCK_STREAM {
        Ok("TCP".to_owned())
    } else if so_type == libc::SOCK_DGRAM {
        Ok("UDP".to_owned())
    } else {
        Err(format!("unknown so_type {}", so_type))
    }
}

#[inline]
fn sockaddr_storage_to_socket_addr(storage: &libc::sockaddr_storage, addr_len: libc::socklen_t) -> String {
    if storage.ss_family == libc::AF_INET as libc::sa_family_t {
        let s = unsafe { &*(storage as *const libc::sockaddr_storage as *const libc::sockaddr_in) };
        let addr = std::net::Ipv4Addr::from(s.sin_addr.s_addr);
        let port = u16::from_be(s.sin_port);
        format!("{}:{}", addr, port)
    } else if storage.ss_family == libc::AF_INET6 as libc::sa_family_t {
        let s = unsafe { &*(storage as *const libc::sockaddr_storage as *const libc::sockaddr_in6) };
        let addr = std::net::Ipv6Addr::from(s.sin6_addr.s6_addr);
        let port = u16::from_be(s.sin6_port);
        format!("{}:{}", addr, port)
    } else if storage.ss_family == libc::AF_UNIX as libc::sa_family_t {
        let s = unsafe { &*(storage as *const libc::sockaddr_storage as *const libc::sockaddr_un) };
        assert!(addr_len >= 1, "addr_len must be at least 1");

        if addr_len as usize >= s.sun_path.len() {
            return "addr len overflow".to_string();
        }

        match String::from_utf8(
            s.sun_path[1..((addr_len - 1) as usize)]
                .iter()
                .cloned()
                .map(|c| c as u8)
                .collect(),
        ) {
            Ok(path) => path,
            Err(_) => "invalid-utf8".to_string(),
        }
    } else {
        format!("unknown protocol {}", storage.ss_family)
    }
}
