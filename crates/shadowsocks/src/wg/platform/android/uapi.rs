use async_trait::async_trait;
use std::fs;
use std::io;

use super::super::uapi::*;

use crate::net::{UnixListener, UnixStream};

const SOCK_DIR: &str = "/var/run/wireguard/";

pub struct AndroidUAPI {}

impl PlatformUAPI for AndroidUAPI {
    type Error = io::Error;
    type Bind = UnixListener;

    fn bind(name: &str) -> Result<UnixListener, io::Error> {
        let socket_path = format!("{}{}.sock", SOCK_DIR, name);
        let _ = fs::create_dir_all(SOCK_DIR);
        let _ = fs::remove_file(&socket_path);
        UnixListener::bind(socket_path)
    }
}

#[async_trait]
impl BindUAPI for UnixListener {
    type Stream = UnixStream;
    type Error = io::Error;

    async fn connect(&self) -> Result<UnixStream, io::Error> {
        let (stream, _) = self.accept().await?;
        Ok(stream)
    }
}
