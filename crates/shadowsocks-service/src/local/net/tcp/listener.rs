//! Local instance listener helpers

use std::io;

use shadowsocks::{canceler::Canceler, config::ServerAddr, lookup_then, net::TcpListener};

use crate::local::context::ServiceContext;

/// Create a standard TCP listener listening on `client_config`
pub async fn create_standard_tcp_listener(
    context: &ServiceContext,
    client_config: &ServerAddr,
    canceler: &Canceler
) -> io::Result<TcpListener> {
    match client_config {
        ServerAddr::SocketAddr(saddr) => TcpListener::bind_with_opts(saddr, context.accept_opts()).await,
        ServerAddr::DomainName(dname, port) => lookup_then!(context.context_ref(), dname, *port, canceler, |addr| {
            TcpListener::bind_with_opts(&addr, context.accept_opts()).await
        })
        .map(|(_, l)| l),
    }
}
