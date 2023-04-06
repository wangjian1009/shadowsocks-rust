use async_trait::async_trait;
use std::error::Error;
use tokio::io::{AsyncRead, AsyncWrite};

#[async_trait]
pub trait BindUAPI {
    type Stream: AsyncRead + AsyncWrite + Unpin;
    type Error: Error;

    async fn connect(&self) -> Result<Self::Stream, Self::Error>;
}

pub trait PlatformUAPI {
    type Error: Error;
    type Bind: BindUAPI;

    fn bind(name: &str) -> Result<Self::Bind, Self::Error>;
}
