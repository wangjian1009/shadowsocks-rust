use hickory_resolver::proto::op::Message;
use std::{net::SocketAddr, sync::Arc};
use tracing::Instrument;

use shadowsocks::{canceler::Canceler, relay::socks5::Address};

use super::super::{dns::{DnsClient, NameServerAddr}, net::UdpInboundWrite};

pub struct DnsProcessor {
    mock_dns_addr: SocketAddr,
    local_addr: Option<Arc<NameServerAddr>>,
    remote_addr: Arc<Address>,
    client: Arc<DnsClient>,
}

impl Drop for DnsProcessor {
    fn drop(&mut self) {
        tracing::info!("DnsProcessor is dropped");
    }
}

impl DnsProcessor {
    pub fn new(
        mock_dns_addr: SocketAddr,
        local_addr: Option<Arc<NameServerAddr>>,
        remote_addr: Arc<Address>,
        client: Arc<DnsClient>,
    ) -> Self {
        DnsProcessor {
            mock_dns_addr,
            local_addr,
            remote_addr,
            client,
        }
    }

    pub fn mock_dns_addr(&self) -> &SocketAddr {
        &self.mock_dns_addr
    }
    
    pub async fn handle_udp_frame(
        &self,
        src_addr: SocketAddr,
        dst_addr: SocketAddr,
        data: &[u8],
        response_writer: super::udp::UdpTunInboundWriter,
        canceler: &Arc<Canceler>,
    ) -> smoltcp::wire::Result<()> {
        let message = match Message::from_vec(data) {
            Ok(m) => m,
            Err(err) => {
                tracing::error!(error = ?err, "query message parse error");
                return Ok(());
            }
        };

        let client = self.client.clone();
        let local_addr = self.local_addr.clone();
        let remote_addr = self.remote_addr.clone();
        let canceler = canceler.clone();
        tokio::spawn(
            async move {
                match client.resolve(message, local_addr.as_ref().map(|e| e.as_ref()), &remote_addr, canceler.as_ref()).await {
                    Ok(response) => {
                        let response = match response.to_vec() {
                            Ok(v) => v,
                            Err(err) => {
                                tracing::error!(error = ?err, "response message serialize error");
                                return;
                            }
                        };

                        if let Err(err) = response_writer
                            .send_to(
                                src_addr,
                                &shadowsocks::relay::Address::SocketAddress(dst_addr),
                                response.as_slice(),
                                canceler.as_ref(),
                            )
                            .await
                        {
                            tracing::error!(error = ?err,  "failed to set packet information, error");
                        }
                    }
                    Err(err) => {
                        tracing::error!(err=?err, "resolve error");
                    }
                }
            }
            .instrument(tracing::info_span!("dns")),
        );
        return Ok(());
    }
}
