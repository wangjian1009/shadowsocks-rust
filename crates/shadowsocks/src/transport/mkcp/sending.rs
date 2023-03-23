use std::{
    collections::LinkedList,
    sync::{
        atomic::{AtomicBool, AtomicU32, Ordering},
        Arc,
    },
};

use bytes::Bytes;
use spin::Mutex;

use super::{
    connection::{MkcpConnMetadata, MkcpConnectionContext, MkcpState},
    segment,
};

struct CacheNodeData {
    pub timeout: u32,
    pub transmit: u32,
    pub seg: segment::DataSegment,
}

struct CacheNode {
    pub number: u32,
    pub data: Mutex<CacheNodeData>,
}

struct SendingWindow {
    cache: Mutex<Vec<Arc<CacheNode>>>,
    total_in_flight_size: AtomicU32,
}

impl SendingWindow {
    fn len(&self) -> u32 {
        self.cache.lock().len() as u32
    }

    fn is_empty(&self) -> bool {
        self.cache.lock().is_empty()
    }

    fn push(&self, number: u32, b: Bytes) {
        let seg = segment::DataSegment {
            timestamp: 0,
            number,
            sending_next: 0,
            payload: Arc::new(b),
        };

        self.cache.lock().push(Arc::new(CacheNode {
            number,
            data: Mutex::new(CacheNodeData {
                timeout: 0,
                transmit: 0,
                seg,
            }),
        }));
    }

    #[inline]
    fn first_number(&self) -> Option<u32> {
        let cache = self.cache.lock();
        cache.get(0).map(|e| e.data.lock().seg.number)
    }

    #[inline]
    fn clear(&self, una: u32) {
        let mut cache = self.cache.lock();
        while let Some(node) = cache.get(0) {
            if node.number >= una {
                break;
            }
            cache.remove(0);
        }
    }

    #[inline]
    fn handle_fast_ack(&self, number: u32, rto: u32) {
        let mut cache = self.cache.lock();
        for node in cache.iter_mut() {
            if number == node.number || number.wrapping_sub(node.number) > 0x7FFFFFFF {
                break;
            }

            let mut data = node.data.lock();
            if data.transmit > 0 && data.timeout > rto / 3 {
                data.timeout -= rto / 3
            }
        }
    }

    #[inline]
    fn total_in_flight_size(&self) -> u32 {
        self.total_in_flight_size.load(Ordering::Relaxed)
    }

    fn collect_to_process(&self, current: &u32, max_in_flight_size: u32) -> LinkedList<Arc<CacheNode>> {
        let mut to_send_segments = LinkedList::new();

        let mut in_flight_size: u32 = 0;

        let cache = self.cache.lock();
        for node in cache.iter() {
            if Arc::strong_count(node) > 1 {
                continue;
            }

            if current.wrapping_sub(node.data.lock().timeout) >= 0x7FFFFFFF {
                continue;
            }

            to_send_segments.push_back(node.clone());
            in_flight_size += 1;
            if in_flight_size < max_in_flight_size {
                continue;
            }
            break;
        }

        to_send_segments
    }

    #[inline]
    fn remove(&self, conn_meta: &MkcpConnMetadata, number: u32) -> bool {
        let mut cache = self.cache.lock();

        for i in 0..cache.len() {
            let node = cache.get(i).unwrap();

            match node.number.cmp(&number) {
                std::cmp::Ordering::Greater => return false,
                std::cmp::Ordering::Equal => {
                    self.total_in_flight_size.fetch_sub(1, Ordering::SeqCst);
                    assert!(self.total_in_flight_size() < 0x7FFFFFFF);
                    cache.remove(i);
                    tracing::trace!(
                        "#{}: sending: remove data segment {}, total-in-flight={}, cache={}",
                        conn_meta,
                        number,
                        self.total_in_flight_size(),
                        cache.len(),
                    );
                    return true;
                }
                std::cmp::Ordering::Less => {}
            }
        }

        false
    }
}

pub struct SendingWorker {
    context: Arc<MkcpConnectionContext>,
    window: SendingWindow,
    first_unacknowledged: AtomicU32,
    next_number: AtomicU32,
    remote_next_number: AtomicU32,
    control_window: AtomicU32,
    window_size: u32,
    first_unacknowledged_updated: AtomicBool,
    closed: AtomicBool,
}

impl SendingWorker {
    pub fn new(context: Arc<MkcpConnectionContext>) -> Self {
        let config = context.config();

        Self {
            context,
            window: SendingWindow {
                cache: Mutex::new(Vec::new()),
                total_in_flight_size: AtomicU32::new(0),
            },
            first_unacknowledged: AtomicU32::new(0),
            next_number: AtomicU32::new(0),
            remote_next_number: AtomicU32::new(32),
            control_window: AtomicU32::new(config.sending_in_flight_size()),
            window_size: config.sending_buffer_size(),
            first_unacknowledged_updated: AtomicBool::new(false),
            closed: AtomicBool::new(false),
        }
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.window.is_empty()
    }

    #[inline]
    pub fn update_necessary(&self) -> bool {
        !self.window.is_empty()
    }

    #[inline]
    pub fn sending_cache_len(&self) -> usize {
        self.window.cache.lock().len()
    }

    pub fn process_segment(&self, current: u32, seg: segment::AckSegment, rto: u32) {
        if self.closed() {
            tracing::error!("#{}: process_segment: closed", self.context.meta());
            return;
        }

        if self.remote_next_number() < seg.receiving_window {
            self.remote_next_number.store(seg.receiving_window, Ordering::SeqCst);
        }

        self.process_receiving_next(seg.receiving_next);

        if seg.is_empty() {
            return;
        }

        let mut maxack = None;
        let mut maxack_removed = None;

        for number in seg.number_list.iter() {
            let number = *number;
            let removed = self.process_ack(number);
            if maxack.is_none() || maxack.unwrap() < number {
                maxack = Some(number);
                maxack_removed = Some(removed);
            }
        }

        if let (Some(maxack), Some(maxack_removed)) = (maxack, maxack_removed) {
            if maxack_removed {
                self.window.handle_fast_ack(maxack, rto);
                let ack_time_span = current.wrapping_sub(seg.timestamp);
                if ack_time_span < 10000 {
                    self.context.round_trip_update(ack_time_span, current);
                }
            }
        }
    }

    #[inline]
    pub fn close_write(&self) {
        self.window.clear(0xFFFFFFFF)
    }

    #[inline]
    pub fn push(&self, b: Bytes) -> bool {
        if self.closed() {
            return false;
        }

        if self.window.len() > self.window_size {
            return false;
        }

        let number = self.next_number.fetch_add(1, Ordering::SeqCst);
        self.window.push(number, b);
        true
    }

    #[inline]
    pub fn release(&self) {
        self.window.cache.lock().clear();
        self.closed.store(true, Ordering::SeqCst);
    }

    #[inline]
    fn on_packet_loss(&self, loss_rate: u32) {
        if !self.context.config().congestion || self.context.round_trip().rto() == 0 {
            return;
        }

        let mut control_window = self.control_window();
        if loss_rate >= 15 {
            control_window = 3 * control_window / 4;
        } else if loss_rate <= 5 {
            control_window += control_window / 4;
        }

        if control_window < 16 {
            control_window = 16;
        }

        if control_window > 2 * self.context.config().sending_in_flight_size() {
            control_window = 2 * self.context.config().sending_in_flight_size();
        }

        self.control_window.store(control_window, Ordering::SeqCst);
    }

    #[inline]
    fn sending_cwnd(&self) -> u32 {
        let mut cwnd = self.context.config_ref().sending_in_flight_size();
        let remote_cwd = self.remote_next_number().wrapping_sub(self.first_unacknowledged());
        if cwnd > remote_cwd {
            cwnd = remote_cwd;
        }

        if self.context.config_ref().congestion && cwnd > self.control_window() {
            cwnd = self.control_window();
        }

        cwnd *= 20; // magic

        cwnd
    }

    pub async fn flush(&self, current: &mut u32) -> bool {
        if self.closed() {
            return false;
        }

        let cwnd = self.sending_cwnd();
        if !self.window.is_empty() {
            // 获取所有需要处理的 segments, 避免在加锁的状态下处理数据
            let mut to_send_segments = self.window.collect_to_process(current, cwnd);

            let mut lost: u32 = 0;
            while let Some(node) = to_send_segments.pop_front() {
                // 再次检测是否在缓存中，如果已经从缓存中删除，代表远端已经接收到，可以直接丢弃
                if Arc::strong_count(&node) == 1 {
                    continue;
                }

                // 原子化Seg状态处理
                let (seg, transmit) = {
                    let mut data = node.data.lock();
                    if data.transmit == 0 {
                        // First time
                        self.window.total_in_flight_size.fetch_add(1, Ordering::SeqCst);
                        if let Some(statistic) = self.context.statistic() {
                            statistic.incr_tx_first(1);
                        }
                    } else {
                        lost += 1;
                        if let Some(statistic) = self.context.statistic() {
                            statistic.incr_tx_retry(1);
                        }
                    }
                    let rto = self.context.round_trip().rto();
                    data.timeout = current.wrapping_add(rto);

                    data.seg.timestamp = *current;
                    data.transmit += 1;

                    let mut option: u8 = 0;
                    if self.context.state() == MkcpState::ReadyToClose {
                        option &= segment::SegmentOption::Close.flag()
                    }

                    data.seg.sending_next = self.first_unacknowledged();

                    (
                        segment::Segment {
                            conv: self.context.meta().conversation,
                            option,
                            data: segment::SegmentData::Data(data.seg.clone()),
                        },
                        data.transmit,
                    )
                };

                match self
                    .context
                    .output()
                    .write(&self.context.meta().remote_addr, &seg)
                    .await
                {
                    Ok(()) => {
                        let state = self.context.state();
                        tracing::trace!(
                            "#{}: ({}): --> {:?} (transmit={})",
                            self.context.meta(),
                            state,
                            seg,
                            transmit
                        );
                    }
                    Err(err) => {
                        let state = self.context.state();
                        tracing::error!(
                            "#{}: ({}): send data segment {} transmit {} error: {}",
                            self.context.meta(),
                            state,
                            node.number,
                            transmit,
                            err,
                        )
                    }
                }

                *current = self.context.elapsed();
                tokio::task::yield_now().await;
            }

            let total_in_flight_size = self.window.total_in_flight_size();
            if !to_send_segments.is_empty() && total_in_flight_size != 0 {
                let rate = lost * 100 / total_in_flight_size;
                self.on_packet_loss(rate);
            }

            self.first_unacknowledged_updated.store(false, Ordering::SeqCst);
        }

        let updated = false;
        self.first_unacknowledged_updated.swap(updated, Ordering::SeqCst);

        updated
    }

    #[inline]
    pub fn process_receiving_next(&self, next_number: u32) {
        self.window.clear(next_number);
        self.find_first_unacknowledged()
    }

    #[inline]
    fn find_first_unacknowledged(&self) {
        let new_value = self.window.first_number().unwrap_or_else(|| self.next_number());
        let old_value = new_value;
        self.first_unacknowledged.swap(old_value, Ordering::SeqCst);

        if old_value != new_value {
            tracing::info!(
                "#{}: first-unacknowledged {} => {}",
                self.context.meta(),
                old_value,
                new_value,
            );
            self.first_unacknowledged_updated.store(true, Ordering::SeqCst);
        }
    }

    #[inline]
    fn process_ack(&self, number: u32) -> bool {
        // number < v.firstUnacknowledged || number >= v.nextNumber
        if number.wrapping_sub(self.first_unacknowledged()) > 0x7FFFFFFF
            || number.wrapping_sub(self.next_number()) < 0x7FFFFFFF
        {
            return false;
        }

        let removed = self.window.remove(self.context.meta(), number);
        if removed {
            self.find_first_unacknowledged();
        }

        removed
    }

    #[inline]
    fn closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed) as _
    }

    #[inline]
    pub fn first_unacknowledged(&self) -> u32 {
        self.first_unacknowledged.load(Ordering::Relaxed) as _
    }

    #[inline]
    pub fn next_number(&self) -> u32 {
        self.next_number.load(Ordering::Relaxed) as _
    }

    #[inline]
    pub fn remote_next_number(&self) -> u32 {
        self.remote_next_number.load(Ordering::Relaxed) as _
    }

    #[inline]
    pub fn control_window(&self) -> u32 {
        self.control_window.load(Ordering::Relaxed) as _
    }
}

#[cfg(test)]
mod test {
    use super::{
        super::{test::collect::*, *},
        segment::*,
        *,
    };
    use tokio::sync::mpsc;

    #[tokio::test]
    #[traced_test]
    async fn basic() {
        let config = Arc::new(MkcpConfig::default());
        let (worker, mut outputs) = create_worker(config.clone());
        let worker = Arc::new(worker);

        // 构造测试数据
        let mut to_send = vec![0u8; 1024 * 1024]; // 1048576
        for i in 0..to_send.len() {
            to_send[i] = i as u8;
        }

        let mss = worker.context.mss() as usize;
        assert!(mss * worker.window_size as usize >= to_send.len());

        let block_count = (to_send.len() / mss) + if to_send.len() % mss > 0 { 1 } else { 0 };

        // 首次发送的数据
        let first_send_count = worker.sending_cwnd() as usize;
        assert!(block_count > first_send_count); // 测试发送情况，一次flush不能发送完成

        // 第二次发送的数据
        let left_count = block_count - first_send_count;

        // 接受窗口大小
        let remote_window_size = config.sending_in_flight_size();

        let mut sending_buf = &mut to_send[..];
        while sending_buf.len() > 0 {
            let block_size = std::cmp::min(mss, sending_buf.len());
            assert_eq!(worker.push(Bytes::copy_from_slice(&sending_buf[..block_size])), true);
            sending_buf = &mut sending_buf[block_size..];
        }

        assert_eq!(worker.window.cache.lock().len(), block_count);
        assert_eq!(worker.next_number(), block_count as u32);
        assert_eq!(worker.window.total_in_flight_size(), 0);

        // worker.

        {
            let worker = worker.clone();
            let remote_window_size = remote_window_size;
            let left_count = left_count;
            tokio::spawn(async move {
                let mut current = worker.context.elapsed();

                // 第一次发送
                assert_eq!(worker.flush(&mut current).await, false);
                assert_eq!(worker.window.total_in_flight_size(), worker.sending_cwnd());

                // 通过ACK清理头部数据
                let mut ack = AckSegment::new();
                ack.receiving_next = 0;
                ack.receiving_window = ack.receiving_next + remote_window_size;
                ack.timestamp = 0;
                for i in 0..left_count {
                    ack.number_list.push(i as u32);
                }
                let huge_rto = worker.context.elapsed() * 2; // 确保重传不会发生
                worker.process_segment(current, ack, huge_rto);

                // 第二次发送
                assert_eq!(worker.flush(&mut current).await, false);
            });
        }

        // 验证发送的数据
        let mut check_buf = &to_send[..];

        // 第一次发送的数据
        for i in 0..first_send_count {
            let seg = outputs.recv().await.unwrap();
            assert_eq!(seg.conv, 1);
            assert_eq!(seg.option, 0);
            assert_matches!(seg.data, SegmentData::Data(..));

            if let SegmentData::Data(data) = seg.data {
                // assert_eq!(data.timestamp, 0);
                assert_eq!(data.number, i as u32);
                assert_eq!(data.sending_next, 0);
                assert_eq!(data.payload.as_ref(), &check_buf[..data.payload.len()]);
                check_buf = &check_buf[data.payload.len()..];
            }
        }

        // 第二次发送的数据
        for i in first_send_count..block_count {
            let seg = outputs.recv().await.unwrap();
            assert_eq!(seg.conv, 1);
            assert_eq!(seg.option, 0);
            assert_matches!(seg.data, SegmentData::Data(..));

            if let SegmentData::Data(data) = seg.data {
                // assert_eq!(data.timestamp, 0);
                assert_eq!(data.number, i as u32);
                assert_eq!(data.sending_next, left_count as u32); // 为了第二次发送，确认了left_count个数据
                assert_eq!(data.payload.as_ref(), &check_buf[..data.payload.len()]);
                check_buf = &check_buf[data.payload.len()..];
            }
        }

        assert_eq!(check_buf.len(), 0);
        assert_eq!(worker.window.total_in_flight_size(), (block_count - left_count) as u32);
    }

    // #[test]
    // #[traced_test]
    // fn rto() {
    //     let config = Arc::new(MkcpConfig::default());
    //     let (worker, mut outputs) = create_worker(config);
    //     let worker = Arc::new(worker);
    // }

    fn create_worker(config: Arc<MkcpConfig>) -> (SendingWorker, mpsc::Receiver<Segment>) {
        let (conn_ctx, outputs) =
            create_connection_ctx(config.clone(), 1, MkcpConnWay::Incoming, "1.1.1.1:1", "2.2.2.2:2", None);
        (SendingWorker::new(Arc::new(conn_ctx)), outputs)
    }
}
