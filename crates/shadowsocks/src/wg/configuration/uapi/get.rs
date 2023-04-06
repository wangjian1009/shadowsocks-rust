use tokio::io::{self, AsyncWrite, AsyncWriteExt};

use super::Configuration;

pub async fn write<W: AsyncWrite + Unpin>(writer: &mut W, key: &'static str, value: String) -> io::Result<()> {
    debug_assert!(value.is_ascii());
    debug_assert!(key.is_ascii());
    tracing::trace!("UAPI: return : {}={}", key, value);
    writer.write_all(key.as_ref()).await?;
    writer.write_all(b"=").await?;
    writer.write_all(value.as_ref()).await?;
    writer.write_all(b"\n").await
}

pub async fn serialize<C: Configuration, W: AsyncWrite + Unpin>(writer: &mut W, config: &C) -> io::Result<()> {
    // serialize interface
    if let Some(sk) = config.get_private_key().await {
        write(writer, "private_key", hex::encode(sk.to_bytes())).await?;
    }

    if let Some(port) = config.get_listen_port().await {
        write(writer, "listen_port", port.to_string()).await?;
    }

    if let Some(fwmark) = config.get_fwmark().await {
        write(writer, "fwmark", fwmark.to_string()).await?;
    }

    // serialize all peers
    let mut peers = config.get_peers().await;
    while let Some(p) = peers.pop() {
        write(writer, "public_key", hex::encode(p.public_key.as_bytes())).await?;
        write(writer, "preshared_key", hex::encode(p.preshared_key)).await?;
        write(writer, "rx_bytes", p.rx_bytes.to_string()).await?;
        write(writer, "tx_bytes", p.tx_bytes.to_string()).await?;
        write(
            writer,
            "persistent_keepalive_interval",
            p.persistent_keepalive_interval.to_string(),
        )
        .await?;

        if let Some((secs, nsecs)) = p.last_handshake_time {
            write(writer, "last_handshake_time_sec", secs.to_string()).await?;
            write(writer, "last_handshake_time_nsec", nsecs.to_string()).await?;
        }

        if let Some(endpoint) = p.endpoint {
            write(writer, "endpoint", endpoint.to_string()).await?;
        }

        for (ip, cidr) in p.allowed_ips {
            write(writer, "allowed_ip", ip.to_string() + "/" + &cidr.to_string()).await?;
        }
    }

    Ok(())
}
