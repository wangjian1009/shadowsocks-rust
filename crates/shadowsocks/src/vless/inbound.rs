use bytes::BytesMut;
use std::{collections::HashMap, future::Future, io, net::SocketAddr, time::Duration};
use tokio::{io::AsyncWriteExt, time};

use crate::transport::StreamConnection;

use super::{
    encoding, mux, new_error,
    packet::{new_vless_packet_connection, VlessUdpReader, VlessUdpWriter},
    protocol,
    protocol::Fallback,
    validator::Validator,
    Config,
};

pub struct InboundHandler {
    validator: Validator,
    fallbacks: Option<HashMap<String, HashMap<String, Fallback>>>,
}

impl InboundHandler {
    pub fn new(cfg: &Config) -> io::Result<Self> {
        let mut handler = Self {
            validator: Validator::new(),
            fallbacks: None,
        };

        for user in cfg.clients.iter() {
            handler.validator.add(user.clone())?
        }

        if let Some(fallbacks) = cfg.fallbacks.as_ref() {
            let mut handler_fallbacks: HashMap<String, HashMap<String, Fallback>> = HashMap::new();
            for fb in fallbacks.iter() {
                if let Some(v) = handler_fallbacks.get_mut(&fb.alpn) {
                    v.insert(fb.path.clone(), fb.clone());
                } else {
                    let mut v = HashMap::new();
                    v.insert(fb.path.clone(), fb.clone());
                    handler_fallbacks.insert(fb.alpn.clone(), v);
                }
            }

            let tmp_fb_key = "".to_owned();
            if let Some(tmp_fb) = handler_fallbacks.get(&tmp_fb_key).map(|e| e.clone()) {
                for (alpn, pfb) in handler_fallbacks.iter_mut() {
                    if alpn != "" {
                        for (path, fb) in tmp_fb.iter() {
                            if !pfb.contains_key(path) {
                                pfb.insert(path.clone(), fb.clone());
                            }
                        }
                    }
                }
            }

            handler.fallbacks = Some(handler_fallbacks);
        }

        Ok(handler)
    }

    // RemoveUser implements proxy.UserManager.RemoveUser().
    #[inline]
    pub fn remove_user(&mut self, email: &str) -> io::Result<()> {
        self.validator.del(email).map(|_| ())
    }

    pub async fn serve<IS, PE, FutPE, PS, FutPS, PU, FutPU>(
        &self,
        mut stream: IS,
        peer_addr: &SocketAddr,
        request_timeout: Option<Duration>,
        serve_stream: PS,
        serve_udp: PU,
        on_error: PE,
    ) -> io::Result<()>
    where
        IS: StreamConnection + 'static,
        // 处理Stream
        FutPS: Future<Output = io::Result<()>> + Send,
        PS: (Fn(Box<dyn StreamConnection + 'static>, protocol::Address) -> FutPS) + Send + Sync + Clone + 'static,
        // 处理Packet
        FutPU: Future<Output = io::Result<()>>,
        PU: (Fn(
                VlessUdpReader<Box<dyn StreamConnection + 'static>>,
                VlessUdpWriter<Box<dyn StreamConnection + 'static>>,
                protocol::Address,
            ) -> FutPU)
            + Send
            + Clone
            + 'static,
        // 处理Error
        FutPE: Future<Output = io::Result<()>>,
        PE: FnOnce(IS, io::Error) -> FutPE,
    {
        let (request, addons, _) = match match request_timeout {
            None => encoding::decode_request_header(&mut stream).await,
            Some(d) => match time::timeout(d, encoding::decode_request_header(&mut stream)).await {
                Ok(r) => r,
                Err(..) => Err(io::Error::new(io::ErrorKind::TimedOut, "decode request header timeout")),
            },
        } {
            Ok(a) => a,
            Err(err) if err.kind() == io::ErrorKind::UnexpectedEof => {
                tracing::debug!(
                    "handshake failed, received EOF before a complete target Address, peer: {}",
                    peer_addr
                );
                return on_error(stream, err).await;
            }
            Err(err) => {
                tracing::warn!(
                    "handshake failed, maybe wrong method or key, or under reply attacks. peer: {}, error: {}",
                    peer_addr,
                    err
                );

                return on_error(stream, err).await;
            }
        };

        let _user = match self.validator.get(&request.user) {
            None => {
                tracing::warn!(
                    "handshake failed. peer: {}, error: user {} invalid",
                    peer_addr,
                    request.user
                );

                return Err(new_error(format!("user {} invalid", request.user)));
            }
            Some(user) => user,
        };

        let mut response = BytesMut::with_capacity(16);
        let response_len = encoding::encode_response_header(&mut response, request.version, &addons)?;
        stream.write(&response[..response_len]).await?;

        match request.command {
            protocol::RequestCommand::TCP => {
                if let Some(address) = request.address {
                    serve_stream(Box::new(stream), address).await
                } else {
                    Err(new_error(format!("TCP rquest no target address")))
                }
            }
            protocol::RequestCommand::UDP => {
                if let Some(address) = request.address {
                    let stream = Box::new(stream) as Box<dyn StreamConnection + 'static>;
                    let (reader, writer) = new_vless_packet_connection(stream);
                    serve_udp(reader, writer, address).await
                } else {
                    Err(new_error(format!("udp rquest no target address")))
                }
            }
            protocol::RequestCommand::Mux => mux::serve(stream, peer_addr, serve_stream, serve_udp).await,
        }
    }
}
