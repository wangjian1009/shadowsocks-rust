use spin::Mutex as SpinMutex;
use std::{future::Future, io, net::SocketAddr, sync::Arc};
use tokio::{io::AsyncReadExt, sync::mpsc};

use crate::{
    transport::{PacketMutWrite, PacketRead, StreamConnection},
    vless::new_error,
};

use super::{
    super::protocol,
    encoding,
    frame,
    session::{Session, SessionContext, SessionManager, SessionMetadata, SessionReadCmd, SessionWay},
    MuxStream,
    SharedStream,
};

pub async fn serve<IS, PS, FutPS, PU, FutPU>(
    stream: IS,
    _peer_addr: &SocketAddr,
    serve_stream: PS,
    serve_udp: PU,
) -> io::Result<()>
where
    IS: StreamConnection + 'static,
    // 处理Stream
    FutPS: Future<Output = io::Result<()>> + Send,
    PS: (Fn(Box<dyn StreamConnection + 'static>, protocol::Address) -> FutPS) + Send + Sync + Clone + 'static,
    // 处理Packet
    FutPU: Future<Output = io::Result<()>>,
    PU: (Fn(Box<dyn PacketRead + 'static>, Box<dyn PacketMutWrite + 'static>, protocol::Address) -> FutPU)
        + Send
        + Clone
        + 'static,
{
    let mut stream = SharedStream::new(stream);
    let session_mgr = Arc::new(SpinMutex::new(SessionManager::new()));
    let (session_context, mut read_done_r) = SessionContext::new(stream.clone());
    let session_context = Arc::new(session_context);

    loop {
        let meta = frame::decode_frame(&mut stream).await?;

        match meta.session_status {
            frame::SessionStatus::Keep => handle_status_keep(&mut stream, &session_mgr, meta, &mut read_done_r).await?,
            frame::SessionStatus::New => {
                handle_status_new(
                    &session_context,
                    &session_mgr,
                    meta,
                    &mut read_done_r,
                    serve_stream.clone(),
                    serve_udp.clone(),
                )
                .await?
            }
            frame::SessionStatus::End => handle_status_end(&mut stream, &session_mgr, meta).await?,
            frame::SessionStatus::KeepAlive => handle_status_keep_alive(&mut stream, meta).await?,
        }
    }
}

async fn handle_status_keep(
    stream: &mut SharedStream,
    session_mgr: &SpinMutex<SessionManager>,
    meta: frame::FrameMetadata,
    read_done_r: &mut mpsc::Receiver<()>,
) -> io::Result<()> {
    if !meta.has_data() {
        return Ok(());
    }

    let session = session_mgr.lock().get(meta.session_id);
    if session.is_none() {
        encoding::write_close_frame(stream, meta.session_id, false).await?;
        encoding::ignore_data(stream, &meta).await?;
    }

    let session = session.unwrap();

    read_data(session.as_ref(), &meta, read_done_r).await
}

async fn handle_status_keep_alive(stream: &mut SharedStream, meta: frame::FrameMetadata) -> io::Result<()> {
    encoding::ignore_data(stream, &meta).await
}

async fn handle_status_new<PS, FutPS, PU, FutPU>(
    session_context: &Arc<SessionContext>,
    session_mgr: &SpinMutex<SessionManager>,
    meta: frame::FrameMetadata,
    read_done_r: &mut mpsc::Receiver<()>,
    serve_stream: PS,
    serve_udp: PU,
) -> io::Result<()>
where
    // 处理Stream
    FutPS: Future<Output = io::Result<()>> + Send,
    PS: (Fn(Box<dyn StreamConnection + 'static>, protocol::Address) -> FutPS) + Send + Sync + 'static,
    // 处理Packet
    FutPU: Future<Output = io::Result<()>>,
    PU: (Fn(Box<dyn PacketRead + 'static>, Box<dyn PacketMutWrite + 'static>, protocol::Address) -> FutPU)
        + Send
        + 'static,
{
    log::info!("received request for {}", meta.target.as_ref().unwrap());

    let session_meta = SessionMetadata {
        way: SessionWay::Incoming,
        target_addr: meta.target.as_ref().unwrap().clone(),
        id: meta.session_id,
    };

    let (read_cmd_s, read_cmd_r) = mpsc::channel(1);

    let session = Arc::new(Session::new(session_meta, session_context.clone(), read_cmd_s));

    {
        let session = session.clone();
        match session.meta().target_addr.network {
            frame::TargetNetwork::UDP => {
                tokio::spawn(async move { handle_serve_udp(session, read_cmd_r, serve_udp).await })
            }
            frame::TargetNetwork::TCP => {
                tokio::spawn(async move { handle_serve_stream(session, read_cmd_r, serve_stream).await })
            }
        };
    }

    session_mgr.lock().add(session.clone());

    read_data(session.as_ref(), &meta, read_done_r).await
}

async fn handle_status_end(
    stream: &mut SharedStream,
    session_mgr: &SpinMutex<SessionManager>,
    meta: frame::FrameMetadata,
) -> io::Result<()> {
    if let Some(_session) = session_mgr.lock().remove(meta.session_id) {
        if meta.has_error() {}
        // if meta.Option.Has(OptionError) {
        //     common.Interrupt(s.input);
        //     common.Interrupt(s.output);
        // }
        // s.Close()
    }

    encoding::ignore_data(stream, &meta).await
}

async fn read_data(
    session: &Session,
    meta: &frame::FrameMetadata,
    read_done_receiver: &mut mpsc::Receiver<()>,
) -> io::Result<()> {
    if !meta.has_data() {
        return Ok(());
    }

    let len = {
        let mut stream = session.context().base_stream();
        stream.read_u16().await? as usize
    };
    if len > 0 {
        session
            .read_cmd_sender()
            .send(SessionReadCmd::Read(len as usize))
            .await
            .map_err(|e| new_error(format!("read_data: send read cmd fail {}", e)))?;
        let _ = read_done_receiver.recv().await;
    }

    Ok(())
}

async fn handle_serve_stream<PS, FutPS>(
    session: Arc<Session>,
    read_cmd_receiver: mpsc::Receiver<SessionReadCmd>,
    serve_stream: PS,
) where
    FutPS: Future<Output = io::Result<()>> + Send,
    PS: (Fn(Box<dyn StreamConnection + 'static>, protocol::Address) -> FutPS) + Send + Sync + 'static,
{
    let target_addr = session.meta().target_addr.address.clone();
    let stream = MuxStream::new(session, read_cmd_receiver);

    tokio::spawn(async move {
        let stream = Box::new(stream);
        serve_stream(stream, target_addr).await
    });
}

async fn handle_serve_udp<PU, FutPU>(
    _session: Arc<Session>,
    _read_cmd_receiver: mpsc::Receiver<SessionReadCmd>,
    _serve_udp: PU,
) where
    FutPU: Future<Output = io::Result<()>>,
    PU: (Fn(Box<dyn PacketRead + 'static>, Box<dyn PacketMutWrite + 'static>, protocol::Address) -> FutPU)
        + Send
        + 'static,
{
}
