use std::{
    sync::{atomic::*, Arc},
    time::Duration,
};

use tokio::sync::mpsc;

use super::{client_stream::ClientStream, protocol::Address, *};

use crate::{
    config::{ServerAddr, ServerConfig, ServerProtocol, ServerType},
    context::Context,
    net::{AcceptOpts, ConnectOpts},
    transport::{
        direct::{TcpAcceptor, TcpConnector},
        Acceptor, Connection, Connector, PacketRead, PacketWrite, StreamConnection,
    },
};

use crate::test::transfer;

type TcpStream = <TcpConnector as Connector>::TS;

mod mux_stream;
mod packet;
mod stream;

async fn connect_mux_stream(
    worker_picker: &mux::WorkerPicker,
    cfg: &Config,
    proxy_port: u16,
    target_addr: Address,
) -> io::Result<mux::MuxStream> {
    let svr_cfg = ServerConfig::new(
        format!("127.0.0.1:{}", proxy_port).parse::<ServerAddr>().unwrap(),
        ServerProtocol::Vless(cfg.clone()),
    );

    let connector = TcpConnector::new(None);
    worker_picker
        .connect_stream(
            &connector,
            &svr_cfg,
            match svr_cfg.protocol() {
                ServerProtocol::Vless(vless_cfg) => vless_cfg,
                _ => unreachable!(),
            },
            target_addr,
            &ConnectOpts::default(),
            |f| f,
        )
        .await
}

async fn connect_stream(cfg: &Config, proxy_port: u16, target_addr: Address) -> io::Result<ClientStream<TcpStream>> {
    let connector = TcpConnector::new(None);

    let svr_cfg = ServerConfig::new(
        format!("127.0.0.1:{}", proxy_port).parse::<ServerAddr>().unwrap(),
        ServerProtocol::Vless(cfg.clone()),
    );

    ClientStream::connect(
        &connector,
        &svr_cfg,
        cfg,
        protocol::RequestCommand::TCP,
        Some(target_addr),
        &ConnectOpts::default(),
        |f| f,
    )
    .await
}

async fn connect_packet(
    cfg: &Config,
    proxy_port: u16,
    target_addr: Address,
) -> io::Result<(
    VlessUdpReader<ClientStream<TcpStream>>,
    VlessUdpWriter<ClientStream<TcpStream>>,
)> {
    let connector = TcpConnector::new(None);

    let svr_cfg = ServerConfig::new(
        format!("127.0.0.1:{}", proxy_port).parse::<ServerAddr>().unwrap(),
        ServerProtocol::Vless(cfg.clone()),
    );

    let stream = ClientStream::connect(
        &connector,
        &svr_cfg,
        cfg,
        protocol::RequestCommand::UDP,
        Some(target_addr.clone().into()),
        &ConnectOpts::default(),
        |f| f,
    )
    .await?;

    Ok(new_vless_packet_connection(stream, target_addr.into()))
}

pub enum DataModifiler {
    // Keep,
    Xor(u8),
}

impl DataModifiler {
    fn update(&self, buf: &mut [u8]) {
        match self {
            // Self::Keep => {}
            Self::Xor(v) => {
                for i in 0..buf.len() {
                    buf[i] = buf[i] ^ v;
                }
            }
        }
    }
}

async fn start_server(
    cfg: &Config,
    modifiler: Arc<DataModifiler>,
) -> io::Result<(tokio::task::JoinHandle<io::Result<()>>, u16)> {
    let context = Context::new(ServerType::Server);
    let addr = "127.0.0.1:0".parse::<ServerAddr>().unwrap();
    let mut acceptor = TcpAcceptor::bind_server_with_opts(&context, &addr, AcceptOpts::default()).await?;
    let port = acceptor.local_addr()?.port();

    let inbound = InboundHandler::new(cfg)?;
    let handler = tokio::spawn(async move {
        let inbound = Arc::new(inbound);
        loop {
            let (connection, peer_addr) = acceptor.accept().await?;
            let stream = match connection {
                Connection::Stream(stream) => stream,
                _ => unreachable!(),
            };

            let peer_addr = peer_addr.unwrap();
            let peer_addr = match peer_addr {
                ServerAddr::SocketAddr(addr) => addr,
                _ => unreachable!(),
            };

            let inbound = inbound.clone();
            let modifiler = modifiler.clone();
            tokio::spawn(async move {
                inbound
                    .serve(
                        stream,
                        &peer_addr,
                        Some(Duration::from_secs(1)),
                        {
                            let modifiler = modifiler.clone();
                            move |s, addr| serve_tcp(s, addr, modifiler.clone())
                        },
                        {
                            let modifiler = modifiler.clone();
                            move |r, w, addr| serve_udp(r, w, addr, modifiler.clone())
                        },
                        move |s, err| serve_err(s, err),
                    )
                    .await
            });
        }
    });

    Ok((handler, port))
}

async fn serve_tcp(
    stream: Box<dyn StreamConnection>,
    target_addr: Address,
    modifiler: Arc<DataModifiler>,
) -> io::Result<()> {
    let total = AtomicU32::new(0);
    let (mut r, mut w) = tokio::io::split(stream);

    match transfer(&mut r, &mut w, move |buf| {
        modifiler.update(buf);
        total.fetch_add(buf.len() as u32, Ordering::SeqCst);
        Ok(())
    })
    .await
    {
        Ok(len) => {
            log::info!("test server to {} transform success, len={}", target_addr, len);
            Ok(())
        }
        Err(err) => {
            log::error!("test server to {} transform complete error {}", target_addr, err);
            Err(err)
        }
    }
}

async fn serve_udp(
    mut r: Box<dyn PacketRead>,
    mut w: Box<dyn PacketWrite>,
    target_addr: Address,
    modifiler: Arc<DataModifiler>,
) -> io::Result<()> {
    let target_addr: ServerAddr = target_addr.into();

    let (channel_w, mut channel_r) = mpsc::channel(1);

    let process_read = {
        let target_addr = target_addr.clone();
        async move {
            let mut recv_buf = vec![0u8; 2048];

            loop {
                match r.read_from(&mut recv_buf).await {
                    Ok((sz, addr)) => {
                        assert_eq!(addr, target_addr);
                        let mut block = Vec::from(&recv_buf[..sz]);

                        modifiler.update(&mut block[..]);
                        match channel_w.send(block).await {
                            Ok(()) => {}
                            Err(err) => {
                                log::error!("test server to {}: channel send error {}", target_addr, err);
                                return Err(io::Error::new(io::ErrorKind::Other, err));
                            }
                        };
                    }
                    Err(err) => {
                        log::error!("test server to {}: read error {}", target_addr, err);
                        return Err(err);
                    }
                }
            }
        }
    };

    let process_write = {
        let target_addr = target_addr.clone();
        async move {
            while let Some(block) = channel_r.recv().await {
                match w.write_to_mut(&block[..], &target_addr).await {
                    Err(err) => {
                        log::error!("test server to {}: write error {}", target_addr, err);
                        return Err(err);
                    }
                    Ok(()) => {}
                }
            }

            Ok(())
        }
    };

    tokio::select! {
        r = process_read => {
            match r {
                Err(err) => {
                    log::error!("test server to {}: read error {}", target_addr, err);
                },
                Ok(()) => {
                    log::error!("test server to {}: read success", target_addr);
                }
            }
        }
        r = process_write => {
            match r {
                Err(err) => {
                    log::error!("test server write error {}", err);
                },
                Ok(()) => {
                    log::error!("test server write success");
                }
            }
        }
    }

    Ok(())
}

async fn serve_err<IS>(_stream: IS, err: io::Error) -> io::Result<()>
where
    IS: StreamConnection + 'static,
{
    Err(err)
}
