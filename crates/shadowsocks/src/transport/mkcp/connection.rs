use arc_swap::ArcSwap;
use bytes::Bytes;
use futures::{ready, FutureExt};
use spin::Mutex as SpinMutex;
use std::{
    fmt::{self, Display},
    io,
    sync::{
        atomic::{AtomicU32, AtomicU8, Ordering},
        Arc,
    },
    task::{self, Poll},
    time::Duration,
};

use tokio::{io::ReadBuf, sync::mpsc, task::JoinHandle, time::Instant};

use crate::ServerAddr;

use super::{
    super::PacketWrite,
    io::MkcpPacketWriter,
    segment,
    utils::Notifier,
    MkcpConfig,
    ReceivingWorker,
    SendingWorker,
    StatisticStat,
};

#[derive(Clone)]
pub struct RoundTripInfo {
    variation: u32,
    srtt: u32,
    rto: u32,
    min_rtt: u32,
    updated_time_stamp: u32,
}

impl RoundTripInfo {
    #[inline]
    fn update_peer_rto(&mut self, rto: u32, current: u32) {
        if current.wrapping_sub(self.updated_time_stamp) < 3000 {
            return;
        }

        self.updated_time_stamp = current;
        self.rto = rto;
    }

    #[inline]
    fn update(&mut self, rtt: u32, current: u32) {
        if rtt > 0x7FFFFFFF {
            return;
        }

        // https://tools.ietf.org/html/rfc6298
        if self.srtt == 0 {
            self.srtt = rtt;
            self.variation = rtt / 2;
        } else {
            let mut delta = rtt.wrapping_sub(self.srtt);
            if self.srtt > rtt {
                delta = self.srtt - rtt;
            }
            self.variation = (3 * self.variation.wrapping_add(delta)) / 4;
            self.srtt = (7 * self.srtt.wrapping_add(rtt)) / 8;
            if self.srtt < self.min_rtt {
                self.srtt = self.min_rtt;
            }
        }

        let mut rto: u32 = if self.min_rtt < 4 * self.variation {
            self.srtt + 4 * self.variation
        } else {
            self.srtt + self.variation
        };

        if rto > 10000 {
            rto = 10000;
        }

        self.rto = rto * 5 / 4;
        self.updated_time_stamp = current;
    }

    pub fn rto(&self) -> u32 {
        self.rto
    }
}

#[derive(Clone, Copy, Debug)]
pub enum UpdaterCmd {
    UpdateDuration(Duration),
    Wakeup,
}

const UPDATER_DATA: &'static str = "data";
const UPDATER_PING: &'static str = "ping";

struct Updater {
    notifier: mpsc::Sender<UpdaterCmd>,
}

impl Updater {
    #[inline]
    fn new() -> (Updater, mpsc::Receiver<UpdaterCmd>) {
        let (s, r) = mpsc::channel(5);
        let updater = Updater { notifier: s };
        (updater, r)
    }
}

macro_rules! set_updater_interval {
    ($ctx:expr, $tag:expr, $reason:expr, $updator:expr, $duration: expr) => {
        match $updator.notifier.try_send(UpdaterCmd::UpdateDuration($duration)) {
            Ok(()) => {}
            Err(err) => {
                let state = $ctx.state();
                log::error!(
                    "#{}: ({}): {}: {}: set_interval fail: {}!",
                    $ctx.meta(),
                    state,
                    $tag,
                    $reason,
                    err
                )
            }
        }
    };
}

macro_rules! wakeup_updater {
    ($ctx:expr, $tag:expr, $reason:expr, $updator:expr) => {
        match $updator.notifier.try_send(UpdaterCmd::Wakeup) {
            Ok(()) => {}
            Err(err) => match err {
                mpsc::error::TrySendError::Full(..) => {}
                mpsc::error::TrySendError::Closed(..) => {
                    let state = $ctx.state();
                    log::trace!(
                        "#{}: ({}): {}: {}: ignore for closed!",
                        $ctx.meta(),
                        state,
                        $tag,
                        $reason,
                    )
                }
            },
        }
    };
}

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum MkcpState {
    Active = 0,          // Connection is active
    ReadyToClose = 1,    // Connection is closed locally
    PeerClosed = 2,      // Connection is closed on remote
    Terminating = 3,     // Connection is ready to be destroyed locally
    PeerTerminating = 4, // Connection is ready to be destroyed on remote
    Terminated = 5,      // Connection is destroyed.
}

impl MkcpState {
    pub fn is_terminating(&self) -> bool {
        match self {
            MkcpState::Terminating | MkcpState::Terminated => true,
            _ => false,
        }
    }

    pub fn is_terminated(&self) -> bool {
        match self {
            MkcpState::Terminated => true,
            _ => false,
        }
    }
}

impl Display for MkcpState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MkcpState::Active => write!(f, "A"),
            MkcpState::ReadyToClose => write!(f, "C"),
            MkcpState::PeerClosed => write!(f, "RC"),
            MkcpState::Terminating => write!(f, "T"),
            MkcpState::PeerTerminating => write!(f, "RT"),
            MkcpState::Terminated => write!(f, "D"),
        }
    }
}

pub enum MkcpConnWay {
    Outgoing,
    Incoming,
}

pub struct MkcpConnMetadata {
    pub way: MkcpConnWay,
    pub local_addr: ServerAddr,
    pub remote_addr: ServerAddr,
    pub conversation: u16,
}

impl Display for MkcpConnMetadata {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match &self.way {
            &MkcpConnWay::Incoming => write!(f, "S {} #{}", self.remote_addr, self.conversation),
            &MkcpConnWay::Outgoing => {
                if self.local_addr.is_unspecified() {
                    write!(f, "C #{}", self.conversation)
                } else {
                    write!(f, "C {} #{}", self.local_addr, self.conversation)
                }
            }
        }
    }
}

pub struct MkcpConnectionContext<PW>
where
    PW: PacketWrite,
{
    config: Arc<MkcpConfig>,
    meta: MkcpConnMetadata,
    remove: Option<Box<dyn Fn() + Send + Sync>>,
    statistic: Option<Arc<StatisticStat>>,
    since: Instant,
    data_input_tx: mpsc::Sender<u8>,
    data_input_rx: SpinMutex<mpsc::Receiver<u8>>,
    data_output: Notifier,
    state: AtomicU8,
    state_begin_time: AtomicU32,
    last_incoming_time: AtomicU32,
    last_ping_time: AtomicU32,
    mss: u32,
    output: Arc<MkcpPacketWriter<PW>>,
    round_trip: ArcSwap<RoundTripInfo>,
    data_updater: Updater,
    ping_updater: Updater,
}

impl<PW> MkcpConnectionContext<PW>
where
    PW: PacketWrite,
{
    pub fn new(
        config: Arc<MkcpConfig>,
        meta: MkcpConnMetadata,
        remove: Option<Box<dyn Fn() + Send + Sync>>,
        output: Arc<MkcpPacketWriter<PW>>,
        statistic: Option<Arc<StatisticStat>>,
    ) -> (Self, mpsc::Receiver<UpdaterCmd>, mpsc::Receiver<UpdaterCmd>) {
        let (data_updater, data_receiver) = Updater::new();
        let (ping_updater, ping_receiver) = Updater::new();
        let (data_input_tx, data_input_rx) = mpsc::channel(1);
        let data_input_rx = SpinMutex::new(data_input_rx);

        let overhead = output.overhead() as u32;

        (
            MkcpConnectionContext {
                config: config.clone(),
                meta,
                remove,
                statistic,
                since: Instant::now(),
                data_input_tx,
                data_input_rx,
                data_output: Notifier::new(),
                state: AtomicU8::new(MkcpState::Active as u8),
                state_begin_time: AtomicU32::new(0),
                last_incoming_time: AtomicU32::new(0),
                last_ping_time: AtomicU32::new(0),
                mss: config.mtu - overhead - segment::DATA_SEGMENT_OVERHEAD as u32,
                output,
                round_trip: ArcSwap::new(Arc::new(RoundTripInfo {
                    rto: 100,
                    min_rtt: config.tti,
                    variation: 0,
                    srtt: 0,
                    updated_time_stamp: 0,
                })),
                data_updater,
                ping_updater,
            },
            data_receiver,
            ping_receiver,
        )
    }

    #[inline]
    pub fn config(&self) -> Arc<MkcpConfig> {
        self.config.clone()
    }

    #[inline]
    pub fn config_ref(&self) -> &MkcpConfig {
        self.config.as_ref()
    }

    #[inline]
    pub fn statistic(&self) -> Option<Arc<StatisticStat>> {
        self.statistic.clone()
    }

    #[inline]
    pub fn meta(&self) -> &MkcpConnMetadata {
        &self.meta
    }

    #[inline]
    pub fn state(&self) -> MkcpState {
        let state = self.state.load(Ordering::Relaxed) as _;
        match state {
            0 => MkcpState::Active,
            1 => MkcpState::ReadyToClose,
            2 => MkcpState::PeerClosed,
            3 => MkcpState::Terminating,
            4 => MkcpState::PeerTerminating,
            5 => MkcpState::Terminated,
            _ => unreachable!(),
        }
    }

    #[inline]
    pub fn state_begin_time(&self) -> u32 {
        self.state_begin_time.load(Ordering::Relaxed) as _
    }

    #[cfg(test)]
    pub fn mss(&self) -> u32 {
        self.mss
    }

    #[inline]
    pub fn output(&self) -> &Arc<MkcpPacketWriter<PW>> {
        &self.output
    }

    #[inline]
    pub fn round_trip(&self) -> Arc<RoundTripInfo> {
        let round_trip = self.round_trip.load();
        round_trip.clone()
    }

    #[inline]
    pub fn round_trip_update(&self, rtt: u32, current: u32) {
        let mut round_trip = self.round_trip.load().as_ref().clone();
        let old_rto = round_trip.rto;
        round_trip.update(rtt, current);
        if old_rto != round_trip.rto {
            log::trace!(
                "#{}: update rto (rtt={}) {} => {}",
                self.meta(),
                rtt,
                old_rto,
                round_trip.rto
            );
            self.round_trip.store(Arc::new(round_trip));
        }
    }

    #[inline]
    pub fn round_trip_update_peer_rto(&self, rto: u32, current: u32) {
        let mut round_trip = self.round_trip.load().as_ref().clone();
        let old_rto = round_trip.rto;
        round_trip.update_peer_rto(rto, current);
        if old_rto != round_trip.rto {
            log::info!("#{}: update peer rto {} => {}", self.meta(), old_rto, round_trip.rto);
            self.round_trip.store(Arc::new(round_trip));
        }
    }

    #[inline]
    pub fn last_incoming_time(&self) -> u32 {
        self.last_incoming_time.load(Ordering::Relaxed) as _
    }

    #[inline]
    pub fn set_last_incoming_time(&self, current: u32) {
        self.last_incoming_time.store(current, Ordering::SeqCst);
    }

    #[inline]
    pub fn last_ping_time(&self) -> u32 {
        self.last_ping_time.load(Ordering::Relaxed) as _
    }

    #[inline]
    pub fn set_last_ping_time(&self, current: u32) {
        self.last_ping_time.store(current, Ordering::SeqCst);
    }

    #[inline]
    pub fn elapsed(&self) -> u32 {
        self.since.elapsed().as_millis() as u32
    }

    #[inline]
    fn set_state(
        &self,
        receiving_worker: &ReceivingWorker<PW>,
        sending_worker: &SendingWorker<PW>,
        state: MkcpState,
        reason: &str,
    ) {
        let current = self.elapsed();

        let old_state = self.state();
        self.state.store(state as u8, Ordering::Relaxed);
        self.state_begin_time.store(current, Ordering::Relaxed);

        log::debug!(
            "#{}: ({}): state ==> {:?}({}) for {} at {}",
            self.meta(),
            old_state,
            state,
            state,
            reason,
            current
        );

        match self.state() {
            MkcpState::Active => {}
            MkcpState::ReadyToClose => receiving_worker.close_read(),
            MkcpState::PeerClosed => sending_worker.close_write(),
            MkcpState::Terminating => {
                receiving_worker.close_read();
                sending_worker.close_write();
                set_updater_interval!(
                    self,
                    UPDATER_PING,
                    "state terminating",
                    self.ping_updater,
                    Duration::from_secs(1)
                );
            }
            MkcpState::PeerTerminating => {
                sending_worker.close_write();
                set_updater_interval!(
                    self,
                    UPDATER_PING,
                    "state peer terminating",
                    self.ping_updater,
                    Duration::from_secs(1)
                );
            }
            MkcpState::Terminated => {
                receiving_worker.close_read();
                sending_worker.close_write();
                set_updater_interval!(
                    self,
                    UPDATER_PING,
                    "state terminated",
                    self.ping_updater,
                    Duration::from_secs(1)
                );
                wakeup_updater!(self, UPDATER_DATA, "state terminated", self.data_updater);
                wakeup_updater!(self, UPDATER_PING, "state terminated", self.ping_updater);

                self.terminate(receiving_worker, sending_worker);
            }
        }
    }

    async fn flush(
        &self,
        receiving_worker: &ReceivingWorker<PW>,
        sending_worker: &SendingWorker<PW>,
    ) -> io::Result<()> {
        let mut current = self.elapsed();

        if self.state() == MkcpState::Terminated {
            return Ok(());
        }

        if self.state() == MkcpState::Active && current.wrapping_sub(self.last_incoming_time()) >= 30000 {
            self.close(receiving_worker, sending_worker)?;
        }

        if self.state() == MkcpState::ReadyToClose && sending_worker.is_empty() {
            self.set_state(
                receiving_worker,
                sending_worker,
                MkcpState::Terminating,
                "send completed",
            );
        }

        if self.state() == MkcpState::Terminating {
            self.ping(
                receiving_worker,
                sending_worker,
                &current,
                segment::Command::Terminate,
                &"flush",
            )
            .await?;

            if current.wrapping_sub(self.state_begin_time()) > 8000 {
                self.set_state(
                    receiving_worker,
                    sending_worker,
                    MkcpState::Terminated,
                    "terminating timeout",
                );
            }
            return Ok(());
        }
        if self.state() == MkcpState::PeerTerminating && current.wrapping_sub(self.state_begin_time()) > 4000 {
            self.set_state(
                receiving_worker,
                sending_worker,
                MkcpState::Terminating,
                "peer terminating timeout",
            );
        }

        if self.state() == MkcpState::ReadyToClose && current.wrapping_sub(self.state_begin_time()) > 15000 {
            self.set_state(
                receiving_worker,
                sending_worker,
                MkcpState::Terminating,
                "ready to close timeout",
            );
        }

        // flush acknowledges
        receiving_worker.flush(&mut current).await;
        if sending_worker.flush(&mut current).await {
            match self
                .ping(
                    receiving_worker,
                    sending_worker,
                    &current,
                    segment::Command::Ping,
                    &"sending updated",
                )
                .await
            {
                Ok(()) => {}
                Err(err) => log::error!("#{}: sending flush send ping segment error: {}", self.meta(), err),
            }
        }

        if current.wrapping_sub(self.last_ping_time()) >= 3000 {
            self.ping(
                receiving_worker,
                sending_worker,
                &current,
                segment::Command::Ping,
                &"tick",
            )
            .await?;
        }

        Ok(())
    }

    fn terminate(&self, receiving_worker: &ReceivingWorker<PW>, sending_worker: &SendingWorker<PW>) {
        let state = self.state();
        log::debug!("#{}: ({}): terminating connection", self.meta(), state);
        let _ = self.data_input_tx.try_send(0);
        self.data_output.signal();

        receiving_worker.release();
        sending_worker.release();

        if let Some(remove) = &self.remove {
            (*remove)()
        }
    }

    fn close(&self, receiving_worker: &ReceivingWorker<PW>, sending_worker: &SendingWorker<PW>) -> io::Result<()> {
        let _ = self.data_input_tx.try_send(0);
        self.data_output.signal();

        match self.state() {
            MkcpState::ReadyToClose | MkcpState::Terminating | MkcpState::Terminated => {
                return Err(io::Error::new(io::ErrorKind::Other, "ErrClosedConnection"));
            }
            MkcpState::Active => {
                self.set_state(receiving_worker, sending_worker, MkcpState::ReadyToClose, "close");
            }
            MkcpState::PeerClosed => {
                self.set_state(receiving_worker, sending_worker, MkcpState::Terminating, "close");
            }
            MkcpState::PeerTerminating => {
                self.set_state(receiving_worker, sending_worker, MkcpState::Terminated, "close");
            }
        }

        log::info!("#{}: closing connection", self.meta());

        Ok(())
    }

    pub async fn ping(
        &self,
        receiving_worker: &ReceivingWorker<PW>,
        sending_worker: &SendingWorker<PW>,
        current: &u32,
        cmd: segment::Command,
        reason: &str,
    ) -> io::Result<()> {
        use segment::*;

        let mut option: u8 = 0;
        if self.state() == MkcpState::ReadyToClose {
            SegmentOption::Close.set_to(&mut option);
        }

        let seg = Segment {
            conv: self.meta().conversation,
            option,
            data: SegmentData::CmdOnlySegment(CmdOnlySegment {
                cmd,
                sending_next: sending_worker.first_unacknowledged(),
                receiving_next: receiving_worker.next_number(),
                peer_rto: self.round_trip().rto(),
            }),
        };

        self.output.write(&self.meta().remote_addr, &seg).await?;
        let state = self.state();
        log::trace!("#{}: ({}): --> {:?} (ping for {})", self.meta(), state, seg, reason);
        self.set_last_ping_time(current.clone());

        Ok(())
    }
}

pub struct MkcpConnection<PW>
where
    PW: PacketWrite,
{
    context: Arc<MkcpConnectionContext<PW>>,
    receiving_worker: Arc<ReceivingWorker<PW>>,
    sending_worker: Arc<SendingWorker<PW>>,
    output_task: JoinHandle<()>,
}

impl<PW> MkcpConnection<PW>
where
    PW: PacketWrite + 'static,
{
    pub fn new(
        config: Arc<MkcpConfig>,
        meta: MkcpConnMetadata,
        remove: Option<Box<dyn Fn() + Send + Sync>>,
        output: Arc<MkcpPacketWriter<PW>>,
        statistic: Option<Arc<StatisticStat>>,
    ) -> Self {
        log::info!("#{}: creating connection", meta);

        let (context, data_receiver, ping_receiver) =
            MkcpConnectionContext::new(config, meta, remove, output, statistic);
        let context = Arc::new(context);

        let receiving_worker = Arc::new(ReceivingWorker::new(context.clone()));
        let sending_worker = Arc::new(SendingWorker::new(context.clone()));

        let output_task = {
            let data_update_interval = Duration::from_millis(context.config.tti as u64);
            let ping_update_interval = Duration::from_secs(5); // 5 seconds
            let context = context.clone();
            let receiving_worker = receiving_worker.clone();
            let sending_worker = sending_worker.clone();

            tokio::spawn(async move {
                Self::process_output(
                    context,
                    receiving_worker,
                    sending_worker,
                    data_receiver,
                    ping_receiver,
                    data_update_interval,
                    ping_update_interval,
                )
                .await
            })
        };

        let conn = MkcpConnection {
            context,
            receiving_worker,
            sending_worker,
            output_task,
        };

        wakeup_updater!(conn.context, UPDATER_PING, "init ping", conn.context.ping_updater);

        conn
    }

    #[inline]
    pub fn state(&self) -> MkcpState {
        self.context.state()
    }

    pub fn input(&self, segments: Vec<segment::Segment>) {
        let current = self.context.elapsed();
        self.context.set_last_incoming_time(current);

        for seg in segments {
            if seg.conv != self.context.meta().conversation {
                let state = self.context.state();
                log::debug!(
                    "#{}: ({}): input: ignore mismatch conv segment: {:?}",
                    self.context.meta(),
                    state,
                    seg
                );
                break;
            }

            let state = self.context.state();
            log::trace!("#{}: ({}): <-- {:?}", self.context.meta(), state, seg);

            let option = seg.option;
            match seg.data {
                segment::SegmentData::Data(seg) => {
                    self.handle_option(option);
                    self.receiving_worker.process_segment(seg);
                    if self.receiving_worker.is_data_available() {
                        match self.context.data_input_tx.try_send(0) {
                            Ok(()) => {
                                // log::info!("xxxxx: data_input signal: success");
                            }
                            Err(mpsc::error::TrySendError::Closed(_message)) => {
                                // log::info!("xxxxx: data_input signal: closed {}", _message);
                            }
                            Err(mpsc::error::TrySendError::Full(_message)) => {
                                // log::info!("xxxxx: data_input signal: full {}", _message);
                            }
                        }
                    }
                    wakeup_updater!(self.context, UPDATER_DATA, "recv data", self.context.data_updater);
                }
                segment::SegmentData::Ack(seg) => {
                    self.handle_option(option);
                    self.sending_worker
                        .process_segment(current, seg, self.context.round_trip().rto());
                    self.context.data_output.signal();
                    wakeup_updater!(self.context, UPDATER_DATA, "recv ack", self.context.data_updater);
                }
                segment::SegmentData::CmdOnlySegment(seg) => {
                    self.handle_option(option);
                    if seg.cmd == segment::Command::Terminate {
                        match self.context.state() {
                            MkcpState::Active | MkcpState::PeerClosed => self.context.set_state(
                                self.receiving_worker.as_ref(),
                                self.sending_worker.as_ref(),
                                MkcpState::PeerTerminating,
                                "cmd terminate",
                            ),
                            MkcpState::ReadyToClose => self.context.set_state(
                                self.receiving_worker.as_ref(),
                                self.sending_worker.as_ref(),
                                MkcpState::Terminating,
                                "cmd terminate",
                            ),
                            MkcpState::Terminating => self.context.set_state(
                                self.receiving_worker.as_ref(),
                                self.sending_worker.as_ref(),
                                MkcpState::Terminated,
                                "cmd terminate",
                            ),
                            _ => {}
                        }
                    }

                    if segment::SegmentOption::Close.is_enable_of(option) || seg.cmd == segment::Command::Terminate {
                        let _ = self.context.data_input_tx.try_send(0);
                        self.context.data_output.signal();
                    }

                    self.sending_worker.process_receiving_next(seg.receiving_next);
                    self.receiving_worker.process_sending_next(seg.sending_next);
                    self.context.round_trip_update_peer_rto(seg.peer_rto, current);
                }
            }
        }
    }

    #[inline]
    pub fn close(&self) -> io::Result<()> {
        self.context
            .close(self.receiving_worker.as_ref(), self.sending_worker.as_ref())?;
        wakeup_updater!(self.context, UPDATER_DATA, "close", self.context.data_updater);
        Ok(())
    }

    #[inline]
    fn handle_option(&self, opt: u8) {
        if segment::SegmentOption::Close.is_enable_of(opt) {
            match self.context.state() {
                MkcpState::ReadyToClose => self.set_state(MkcpState::Terminating, "cmd option close"),
                MkcpState::Active => self.set_state(MkcpState::PeerClosed, "cmd option close"),
                _ => {}
            }
        }
    }

    #[inline]
    fn set_state(&self, state: MkcpState, reason: &str) {
        self.context.set_state(
            self.receiving_worker.as_ref(),
            self.sending_worker.as_ref(),
            state,
            reason,
        );
    }

    #[inline]
    pub fn meta(&self) -> &MkcpConnMetadata {
        self.context.meta()
    }

    pub fn poll_read(&self, cx: &mut task::Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        loop {
            match self.context.state() {
                MkcpState::ReadyToClose | MkcpState::Terminating | MkcpState::Terminated => {
                    // let state = self.context.state();
                    // log::info!("#{}: read done in state {:?}", self.context.meta(), state);
                    return Poll::Ready(Ok(()));
                }
                MkcpState::Active | MkcpState::PeerClosed | MkcpState::PeerTerminating => {
                    let readed = self.receiving_worker.read(buf);
                    if readed > 0 {
                        // log::info!("#{}: received {} data", self.context.meta(), readed);
                        wakeup_updater!(self.context, "poll read", UPDATER_DATA, self.context.data_updater);
                        return Poll::Ready(Ok(()));
                    } else {
                        // log::info!("#{}: recv begin wait", self.context.meta());
                        ready!(self.context.data_input_rx.lock().recv().boxed_local().poll_unpin(cx));
                    }
                }
            }
        }
    }

    pub fn poll_write(&self, cx: &mut task::Context<'_>, mut buf: &[u8]) -> Poll<io::Result<usize>> {
        let mut update_pending = false;
        let mut writed_size = 0;

        loop {
            loop {
                if self.context.state() != MkcpState::Active {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        format!("connection not active"),
                    )));
                }

                if buf.len() == 0 {
                    break;
                }

                let block_size = std::cmp::min(self.context.mss as usize, buf.len());
                let block = Bytes::copy_from_slice(&buf[..block_size]);
                if !self.sending_worker.push(block) {
                    break;
                }

                update_pending = true;
                writed_size += block_size;

                buf = &buf[block_size..];
            }

            if update_pending {
                wakeup_updater!(
                    self.context,
                    UPDATER_DATA,
                    format!("writed {} bytes", writed_size),
                    self.context.data_updater
                );
                update_pending = false;
            }

            if buf.len() == 0 || writed_size > 0 {
                break;
            }

            ready!(self.context.data_output.wait().boxed().poll_unpin(cx));
        }

        Poll::Ready(Ok(writed_size))
    }

    async fn process_output(
        context: Arc<MkcpConnectionContext<PW>>,
        receiving_worker: Arc<ReceivingWorker<PW>>,
        sending_worker: Arc<SendingWorker<PW>>,
        mut data_receiver: mpsc::Receiver<UpdaterCmd>,
        mut ping_receiver: mpsc::Receiver<UpdaterCmd>,
        mut data_update_interval: Duration,
        mut ping_update_interval: Duration,
    ) {
        let mut data_is_wakeup = false;
        let mut data_next_process = Instant::now();
        let mut ping_next_process = Instant::now();

        while !context.state().is_terminated() {
            let now = Instant::now();

            let data_delay = tokio::time::sleep(if data_next_process > now {
                data_next_process - now
            } else {
                Duration::from_secs(0)
            });

            let ping_delay = tokio::time::sleep(if ping_next_process > now {
                ping_next_process - now
            } else {
                Duration::from_secs(0)
            });

            let is_terminating = context.state().is_terminating();
            tokio::select! {
                cmd = data_receiver.recv(), if !is_terminating  => {
                    match cmd {
                        Some(UpdaterCmd::UpdateDuration(duration)) => {
                            let state = context.state();
                            log::debug!("#{}: ({}): {}: interval {:?} ==> {:?}", context.meta(), state, UPDATER_DATA, data_update_interval, duration);
                            data_next_process -= data_update_interval;
                            data_next_process += duration;
                            data_update_interval = duration;
                        }
                        Some(UpdaterCmd::Wakeup) => {
                            if !data_is_wakeup {
                                data_next_process = Instant::now();
                                data_is_wakeup = true;
                                let state = context.state();
                                log::debug!("#{}: ({}): {}: wakeup", context.meta(), state, UPDATER_DATA);
                            }
                        }
                        None => {}
                    };
                },
                _ = data_delay , if !is_terminating && data_is_wakeup => {
                    log::trace!(
                        "#{}: flush for data: sending-cache={} receiving-cache={} ack-list={} rto={}",
                        context.meta(),
                        sending_worker.sending_cache_len(),
                        receiving_worker.receiving_cache_len(),
                        receiving_worker.ack_list_count(),
                        context.round_trip().rto(),
                    );

                    match context.flush(receiving_worker.as_ref(), sending_worker.as_ref()).await {
                        Ok(()) => {}
                        Err(err) => {
                            log::error!("#{}: {}: flush(data) error {}", context.meta(), UPDATER_DATA, err);
                        }
                    };

                    data_next_process = Instant::now() + data_update_interval;
                    data_is_wakeup = sending_worker.update_necessary() || receiving_worker.update_necessary();
                    if !data_is_wakeup {
                        let state = context.state();
                        log::debug!("#{}: ({}): {}: suspend", context.meta(), state, UPDATER_DATA);
                    }
                },
                cmd = ping_receiver.recv() => {
                    match cmd {
                        Some(UpdaterCmd::UpdateDuration(duration)) => {
                            let state = context.state();
                            log::debug!("#{}: ({}): {}: interval {:?} ==> {:?}", context.meta(), state, UPDATER_PING, ping_update_interval, duration);
                            ping_update_interval = duration;
                        }
                        Some(UpdaterCmd::Wakeup) => {}
                        None => {}
                    };
                },
                _ = ping_delay => {
                    log::trace!(
                        "#{}: flush for ping: sending-cache={} receiving-cache={} ack-list={} rto={}",
                        context.meta(),
                        sending_worker.sending_cache_len(),
                        receiving_worker.receiving_cache_len(),
                        receiving_worker.ack_list_count(),
                        context.round_trip().rto(),
                    );

                    match context.flush(receiving_worker.as_ref(), sending_worker.as_ref()).await {
                        Ok(()) => {}
                        Err(err) => {
                            log::error!("#{}: {}: flush(ping) error {}", context.meta(), UPDATER_PING, err);
                        }
                    };

                    ping_next_process = Instant::now() + ping_update_interval;
                },
            }
        }
    }
}

impl<PW> Drop for MkcpConnection<PW>
where
    PW: PacketWrite,
{
    fn drop(&mut self) {
        self.output_task.abort();
        log::info!("#{}: connection droped", self.context.meta());
    }
}

#[cfg(test)]
mod test {
    use super::{super::test::collect::*, segment::*, *};
    use std::assert_matches::assert_matches;

    #[tokio::test]
    async fn basic_data_first() {
        let config = Arc::new(MkcpConfig::default());
        let (conn, mut outputs) =
            create_connection(config.clone(), 1, MkcpConnWay::Incoming, "1.1.1.1:1", "2.2.2.2:2", None);

        conn.input(vec![segment::Segment {
            conv: 1,
            option: 0,
            data: SegmentData::Data(DataSegment {
                timestamp: 1,
                number: 0,
                sending_next: 0,
                payload: Arc::new(Bytes::copy_from_slice(b"abcd")),
            }),
        }]);

        let seg = outputs.recv().await.unwrap();

        assert_eq!(seg.conv, 1);
        assert_eq!(seg.option, 0);

        assert_matches!(seg.data, SegmentData::Ack(..));
        if let SegmentData::Ack(ack) = seg.data {
            assert_eq!(ack.receiving_next, 0);
            assert_eq!(ack.receiving_window, config.receiving_in_flight_size());
            assert_eq!(ack.number_list, vec![0]);
        }

        conn.input(vec![segment::Segment {
            conv: 1,
            option: 0,
            data: SegmentData::Data(DataSegment {
                timestamp: 2,
                number: 1,
                sending_next: 0,
                payload: Arc::new(Bytes::copy_from_slice(b"abcd")),
            }),
        }]);

        let seg = outputs.recv().await.unwrap();
        assert_matches!(seg.data, SegmentData::Ack(..));
        if let SegmentData::Ack(ack) = seg.data {
            assert_eq!(ack.receiving_next, 0);
            assert_eq!(ack.receiving_window, config.receiving_in_flight_size());
            assert_eq!(ack.number_list, vec![1, 0]);
            assert_eq!(ack.timestamp, 2);
        }
    }
}
