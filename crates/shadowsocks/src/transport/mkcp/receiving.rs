use std::{
    collections::{BTreeMap, LinkedList},
    io,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
};

use bytes::Bytes;
use spin::Mutex;
use tracing::trace;

use super::{
    connection::{MkcpConnectionContext, MkcpState},
    segment,
};

use tokio::io::ReadBuf;

struct ReceivingWindow {
    cache: BTreeMap<u32, segment::DataSegment>,
}

impl ReceivingWindow {
    fn new() -> Self {
        Self { cache: BTreeMap::new() }
    }

    #[inline]
    fn set(&mut self, id: u32, value: segment::DataSegment) -> bool {
        if let std::collections::btree_map::Entry::Vacant(e) = self.cache.entry(id) {
            e.insert(value);
            true
        } else {
            false
        }
    }

    #[inline]
    fn has(&self, id: &u32) -> bool {
        match self.cache.get(id) {
            Some(..) => true,
            None => false,
        }
    }

    #[inline]
    fn remove(&mut self, id: &u32) -> Option<segment::DataSegment> {
        self.cache.remove(id)
    }
}

struct Ack {
    timestamp: u32,
    number: u32,
    next_flush: u32,
}

struct AckList {
    acks: Vec<Ack>,
    dirty: bool,
}

impl AckList {
    fn new() -> Self {
        Self {
            acks: Vec::new(),
            dirty: false,
        }
    }

    fn add(&mut self, number: u32, timestamp: u32) {
        self.acks.push(Ack {
            timestamp,
            number,
            next_flush: 0,
        });
        self.dirty = true;
    }

    fn clear(&mut self, una: u32) {
        let mut removed_count = 0;

        let mut i = 0;
        while i < self.acks.len() {
            let node = &self.acks[i];
            if node.number < una {
                removed_count += 1;
                self.acks.remove(i);
            } else {
                i += 1;
            }
        }

        if removed_count > 0 {
            self.dirty = true
        }
    }

    fn flush(&mut self, to_send_segments: &mut LinkedList<segment::AckSegment>, current: &u32, rto: u32) {
        let mut flush_candidates = Vec::with_capacity(segment::ACK_NUMBER_LIMIT);

        let mut seg = segment::AckSegment::new();

        for node in self.acks.iter_mut() {
            if &node.next_flush > current {
                if flush_candidates.len() < segment::ACK_NUMBER_LIMIT {
                    flush_candidates.push(node.number);
                }
                continue;
            }
            seg.put_number(node.number);
            seg.put_timestamp(node.timestamp);
            let timeout: u32 = std::cmp::max(rto / 2, 20);
            node.next_flush = current.wrapping_add(timeout);

            if seg.is_full() {
                to_send_segments.push_back(seg);
                seg = segment::AckSegment::new();
                self.dirty = false;
            }
        }

        if self.dirty || !seg.is_empty() {
            for number in flush_candidates.iter() {
                if seg.is_full() {
                    break;
                }
                seg.put_number(*number);
            }
            to_send_segments.push_back(seg);
            self.dirty = false;
        }
    }
}

pub struct ReceivingWorker {
    context: Arc<MkcpConnectionContext>,
    left_over: Mutex<Option<Bytes>>,
    window: Mutex<ReceivingWindow>,
    ack_list: Mutex<AckList>,
    next_number: AtomicU32,
    window_size: u32,
}

impl ReceivingWorker {
    pub fn new(context: Arc<MkcpConnectionContext>) -> Self {
        let window_size = context.config().receiving_in_flight_size();
        Self {
            context,
            left_over: Mutex::new(None),
            window: Mutex::new(ReceivingWindow::new()),
            ack_list: Mutex::new(AckList::new()),
            next_number: AtomicU32::new(0),
            window_size,
        }
    }

    #[inline]
    pub fn process_sending_next(&self, number: u32) {
        self.ack_list.lock().clear(number)
    }

    #[inline]
    pub fn process_segment(&self, seg: segment::DataSegment) {
        let number = seg.number;
        let idx = number.wrapping_sub(self.next_number());
        if idx >= self.window_size {
            if let Some(statistic) = self.context.statistic() {
                statistic.incr_rx_ignore(1);
            }
            return;
        }

        {
            let mut ack_list = self.ack_list.lock();
            ack_list.clear(seg.sending_next);
            ack_list.add(number, seg.timestamp);
        }

        let is_first = self.window.lock().set(seg.number, seg);

        if let Some(statistic) = self.context.statistic() {
            if is_first {
                statistic.incr_rx_first(1);
            } else {
                statistic.incr_rx_ignore(1);
            }
        }
    }

    #[inline]
    pub fn is_data_available(&self) -> bool {
        self.window.lock().has(&self.next_number())
    }

    #[inline]
    pub fn release(&self) {}

    #[inline]
    pub fn close_read(&self) {}

    #[inline]
    pub fn next_number(&self) -> u32 {
        self.next_number.load(Ordering::Relaxed)
    }

    #[inline]
    pub fn read(&self, buf: &mut ReadBuf<'_>) -> usize {
        let mut readed: usize = 0;

        {
            let mut left_over = self.left_over.lock();
            if let Some(bytes) = left_over.as_mut() {
                let buf_capacity = buf.remaining();
                if bytes.len() > buf_capacity {
                    buf.put_slice(&bytes[..buf_capacity]);
                    let _ = bytes.split_to(buf_capacity);
                    return buf_capacity;
                } else {
                    readed = bytes.len();
                    buf.put_slice(&bytes[..])
                }
            }

            *left_over = None;
        }

        while buf.remaining() > 0 {
            let bytes = match {
                let next_number = self.next_number();
                let mut window = self.window.lock();
                window.remove(&next_number)
            } {
                Some(seg) => {
                    self.next_number.fetch_add(1, Ordering::SeqCst);
                    seg.payload
                }
                None => break,
            };

            let read_count = std::cmp::min(buf.remaining(), bytes.len());
            buf.put_slice(&bytes[..read_count]);
            readed += read_count;

            if read_count < bytes.len() {
                let mut left_over = self.left_over.lock();
                *left_over = Some(Bytes::copy_from_slice(&bytes[read_count..]));
            }
        }

        readed
    }

    #[inline]
    pub fn update_necessary(&self) -> bool {
        !self.ack_list.lock().acks.is_empty()
    }

    #[inline]
    pub fn receiving_cache_len(&self) -> usize {
        self.window.lock().cache.len()
    }

    #[inline]
    pub fn ack_list_count(&self) -> usize {
        self.ack_list.lock().acks.len()
    }

    pub async fn flush(&self, current: &mut u32) {
        let mut to_send_segments = LinkedList::new();

        let rto = self.context.round_trip().rto();
        self.ack_list.lock().flush(&mut to_send_segments, current, rto);

        while let Some(seg) = to_send_segments.pop_front() {
            match self.write(seg).await {
                Ok(()) => {}
                Err(err) => tracing::error!(
                    "#{}: sending flush send data segment error: {}",
                    self.context.meta(),
                    err
                ),
            };
            *current = self.context.elapsed();
        }
    }

    async fn write(&self, mut seg: segment::AckSegment) -> io::Result<()> {
        use segment::*;

        let mut option: u8 = 0;
        if self.context.state() == MkcpState::ReadyToClose {
            option &= segment::SegmentOption::Close.flag();
        }

        let next_number = self.next_number();
        seg.receiving_window = next_number + self.window_size;
        seg.receiving_next = next_number;

        let seg = Segment {
            conv: self.context.meta().conversation,
            option,
            data: SegmentData::Ack(seg),
        };

        self.context
            .output()
            .write(&self.context.meta().remote_addr, &seg)
            .await?;
        let state = self.context.state();
        trace!("#{}: ({}): --> {:?}", self.context.meta(), state, seg,);
        Ok(())
    }
}

// #[cfg(test)]
// mod test {
//     use super::{
//         super::{test::collect::*, *},
//         segment::*,
//         *,
//     };

//     #[test]
//     fn read_basic() {
//         let config = Arc::new(MkcpConfig::default());
//         let (conn_ctx, _outputs) =
//             create_connection_ctx(config.clone(), 1, MkcpConnWay::Incoming, "1.1.1.1:1", "2.2.2.2:2", None);
//         let worker = ReceivingWorker::new(Arc::new(conn_ctx));

//         worker.process_segment(DataSegment {
//             timestamp: 1,
//             number: 0,
//             sending_next: 0,
//             payload: Arc::new(Bytes::copy_from_slice(b"aaaa")),
//         });

//         worker.process_segment(DataSegment {
//             timestamp: 2,
//             number: 1,
//             sending_next: 0,
//             payload: Arc::new(Bytes::copy_from_slice(b"bbbb")),
//         });

//         worker.process_segment(DataSegment {
//             timestamp: 3,
//             number: 2,
//             sending_next: 0,
//             payload: Arc::new(Bytes::copy_from_slice(b"cccc")),
//         });

//         assert_eq!(worker.window.lock().cache.len(), 3);
//         assert_eq!(worker.next_number(), 0);

//         let mut buf = vec![0; 2];
//         assert_eq!(worker.read(&mut ReadBuf::new(&mut buf)), 2);
//         assert_eq!(worker.window.lock().cache.len(), 2);
//         assert_eq!(worker.next_number(), 1);
//         assert_eq!(buf, b"aa");

//         let mut buf = vec![0; 1];
//         assert_eq!(worker.read(&mut ReadBuf::new(&mut buf)), 1);
//         assert_eq!(worker.window.lock().cache.len(), 2);
//         assert_eq!(worker.next_number(), 1);
//         assert_eq!(buf, b"a");

//         let mut buf = vec![0; 3];
//         assert_eq!(worker.read(&mut ReadBuf::new(&mut buf)), 3);
//         assert_eq!(worker.window.lock().cache.len(), 1);
//         assert_eq!(worker.next_number(), 2);
//         assert_eq!(buf, b"abb");

//         let mut buf = vec![0; 2];
//         assert_eq!(worker.read(&mut ReadBuf::new(&mut buf)), 2);
//         assert_eq!(worker.window.lock().cache.len(), 1);
//         assert_eq!(worker.next_number(), 2);
//         assert_eq!(buf, b"bb");

//         let mut buf = vec![0; 100];
//         assert_eq!(worker.read(&mut ReadBuf::new(&mut buf)), 4);
//         assert_eq!(worker.window.lock().cache.len(), 0);
//         assert_eq!(worker.next_number(), 3);
//         assert_eq!(&buf[..4], b"cccc");
//     }
// }
