use spin::Mutex as SpinMutex;
use std::{future::Future, io, sync::Arc};
use tokio::{io::AsyncReadExt, sync::mpsc};

use crate::{
    config::ServerConfig,
    net::ConnectOpts,
    transport::{Connector, StreamConnection},
    vless::new_error,
};

use super::{
    super::{protocol, ClientStream, Config},
    encoding,
    frame::{self, Destination, TargetNetwork},
    session::{Session, SessionContext, SessionManager, SessionMetadata, SessionReadCmd, SessionWay},
    shared_stream::SharedStream,
    stream::MuxStream,
};

#[derive(Clone, Debug, PartialEq)]
pub struct ClientStrategy {
    pub max_concurrency: usize,
    pub max_connection: usize,
}

impl Default for ClientStrategy {
    fn default() -> Self {
        Self {
            max_concurrency: 0,
            max_connection: 128,
        }
    }
}

struct ClientWorkerContext {
    max_id: u16,
    context: Arc<SessionContext>,
    session_manager: SessionManager,
}

impl ClientWorkerContext {
    fn new(context: Arc<SessionContext>) -> Self {
        Self {
            max_id: 0,
            context,
            session_manager: SessionManager::new(),
        }
    }

    fn new_session(&mut self, target_addr: Destination) -> (Arc<Session>, mpsc::Receiver<SessionReadCmd>) {
        self.max_id += 1;
        let session_meta = SessionMetadata {
            way: SessionWay::Outgoing,
            target_addr,
            id: self.max_id,
        };

        let (read_cmd_s, read_cmd_r) = mpsc::channel(1);

        let session = Session::new(session_meta, self.context.clone(), read_cmd_s);

        let session = Arc::new(session);

        self.session_manager.add(session.clone());

        (session, read_cmd_r)
    }
}

pub struct ClientWorker {
    context: SpinMutex<ClientWorkerContext>,
    strategy: Arc<ClientStrategy>,
}

impl ClientWorker {
    pub fn new(strategy: Arc<ClientStrategy>, base_stream: SharedStream) -> Self {
        let (session_context, read_done_r) = SessionContext::new(base_stream);
        let _read_done_receiver = Arc::new(read_done_r);

        Self {
            context: SpinMutex::new(ClientWorkerContext::new(Arc::new(session_context))),
            strategy,
        }
    }

    pub fn connect(&self, target_addr: Destination) -> io::Result<MuxStream> {
        let (session, read_cmd_r) = self.context.lock().new_session(target_addr);
        MuxStream::connect(session, read_cmd_r)
    }

    #[inline]
    pub fn session_context(&self) -> Arc<SessionContext> {
        self.context.lock().context.clone()
    }

    pub fn is_closing(&self) -> bool {
        let count = self.context.lock().session_manager.count();
        if self.strategy.max_connection > 0 && count >= self.strategy.max_connection {
            return true;
        }
        false
    }

    pub fn is_full(&self) -> bool {
        if self.is_closing() || self.closed() {
            return true;
        }

        let count = self.context.lock().session_manager.count();
        if self.strategy.max_concurrency > 0 && count >= self.strategy.max_concurrency {
            return true;
        }

        false
    }

    pub fn closed(&self) -> bool {
        false
    }
}

pub struct WorkerPicker {
    workers: SpinMutex<Vec<Arc<ClientWorker>>>,
}

impl WorkerPicker {
    pub fn new() -> Self {
        Self {
            workers: SpinMutex::new(Vec::new()),
        }
    }

    pub async fn connect_stream<C, S, F>(
        &self,
        connector: &C,
        svr_cfg: &ServerConfig,
        svr_vless_cfg: &Config,
        target_address: protocol::Address,
        opts: &ConnectOpts,
        map_fn: F,
    ) -> io::Result<MuxStream>
    where
        C: Connector,
        S: StreamConnection + 'static,
        F: FnOnce(C::TS) -> S,
    {
        let strategy = match svr_vless_cfg.mux.as_ref() {
            Some(strategy) => strategy.clone(),
            None => return Err(new_error("")),
        };

        let worker = self
            .pick_available(move || async move {
                let stream = ClientStream::connect(
                    connector,
                    svr_cfg,
                    svr_vless_cfg,
                    protocol::RequestCommand::Mux,
                    None,
                    opts,
                    map_fn,
                )
                .await?;

                let stream = SharedStream::new(stream);

                Ok(ClientWorker::new(Arc::new(strategy), stream))
            })
            .await?;

        worker.connect(Destination {
            network: TargetNetwork::TCP,
            address: target_address,
        })
    }

    pub async fn pick_available<F, FutF>(&self, create: F) -> io::Result<Arc<ClientWorker>>
    where
        FutF: Future<Output = io::Result<ClientWorker>>,
        F: FnOnce() -> FutF,
    {
        if let Some(worker) = self.pick_internal() {
            return Ok(worker);
        }

        self.cleanup();

        let worker = Arc::new(create().await?);

        {
            let worker = worker.clone();
            tokio::spawn(async move { Self::serve(worker).await });
        }

        self.workers.lock().push(worker.clone());

        Ok(worker)
    }

    async fn serve(worker: Arc<ClientWorker>) -> io::Result<()> {
        let mut stream = worker.session_context().base_stream();
        loop {
            let meta = frame::decode_frame(&mut stream).await?;

            match meta.session_status {
                frame::SessionStatus::Keep => {
                    if meta.has_data() {
                        let len = stream.read_u16().await? as usize;
                        if len > 0 {
                            //     session
                            //         .read_cmd_sender()
                            //         .send(SessionReadCmd::Read(len as usize))
                            //         .await
                            //         .map_err(|e| new_error(format!("read_data: send read cmd fail {}", e)))?;
                            //     let _ = read_done_receiver.recv().await;
                        }
                    }
                }
                frame::SessionStatus::End => {
                    // if let Some(_session) = session_mgr.lock().remove(meta.session_id) {
                    //     if meta.has_error() {}
                    //     // if meta.Option.Has(OptionError) {
                    //     //     common.Interrupt(s.input);
                    //     //     common.Interrupt(s.output);
                    //     // }
                    //     // s.Close()
                    // }

                    encoding::ignore_data(&mut stream, &meta).await?
                }
                frame::SessionStatus::New => encoding::ignore_data(&mut stream, &meta).await?,
                frame::SessionStatus::KeepAlive => encoding::ignore_data(&mut stream, &meta).await?,
            }
        }
    }

    #[inline]
    fn find_available(workers: &Vec<Arc<ClientWorker>>) -> Option<usize> {
        for i in 0..workers.len() {
            if !workers[i].is_full() {
                return Some(i);
            }
        }

        None
    }

    fn pick_internal(&self) -> Option<Arc<ClientWorker>> {
        let mut workers = self.workers.lock();

        if let Some(idx) = Self::find_available(&workers) {
            let n = workers.len();
            if n > 1 && idx != n - 1 {
                workers.swap(idx, n - 1);
            }
            return Some(workers[idx].clone());
        }

        None
    }

    fn cleanup(&self) {
        let mut workers = self.workers.lock();

        let mut i = 0;
        while i < workers.len() {
            if workers[i].closed() {
                workers.swap_remove(i);
            } else {
                i += 1;
            }
        }
    }
}

impl Default for WorkerPicker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod test {
    use crate::vless::new_error;

    use super::*;

    #[tokio::test]
    async fn picker_failure() {
        let picker = WorkerPicker::new();

        let r = picker.pick_available(|| async { Err(new_error("test")) }).await;
        assert!(r.is_err());
    }
}
