use std::{
    net::SocketAddr,
    sync::Arc,
    task::{Context, Poll, Waker},
    time::{Duration, Instant},
};

use futures::future;

use crate::net::UdpSocket;

use super::super::{HeaderPolicy, Security};

use super::{
    config::KcpConfig,
    io::{DecorateOutput, UdpOutput},
    kcp::{Error as KcpError, Kcp, KcpResult},
    utils::now_millis,
};

pub struct KcpSocket {
    kcp: Kcp<DecorateOutput<UdpOutput>>,
    last_update: Instant,
    socket: Arc<UdpSocket>,
    // header: Option<Arc<HeaderPolicy>>,
    // security: Option<Arc<Security>>,
    flush_write: bool,
    flush_ack_input: bool,
    sent_first: bool,
    pending_sender: Option<Waker>,
    pending_receiver: Option<Waker>,
    closed: bool,
}

impl KcpSocket {
    pub fn new(
        c: &KcpConfig,
        conv: u32,
        socket: Arc<UdpSocket>,
        target_addr: SocketAddr,
        stream: bool,
        header: Option<Arc<HeaderPolicy>>,
        security: Option<Arc<Security>>,
    ) -> KcpResult<KcpSocket> {
        let mut overhead = 0;
        if let Some(header) = header.as_ref() {
            overhead += header.size();
        }

        if let Some(security) = security.as_ref() {
            overhead += security.overhead();
        }

        let mut presend_buf = None;
        if overhead > 0 {
            presend_buf = Some(Vec::with_capacity(c.mtu));
            unsafe { presend_buf.as_mut().unwrap().set_len(c.mtu) };
        }

        if c.mtu < overhead {
            return Err(KcpError::InvalidMtu(c.mtu));
        }

        let output = DecorateOutput::new(
            UdpOutput::new(socket.clone(), target_addr),
            header.clone(),
            security,
            presend_buf,
        );
        let mut kcp = if stream {
            Kcp::new_stream(conv, output)
        } else {
            Kcp::new(conv, output)
        };

        kcp.set_mtu(c.mtu - overhead)?;
        kcp.set_nodelay(c.nodelay.nodelay, c.nodelay.interval, c.nodelay.resend, c.nodelay.nc);
        kcp.set_wndsize(c.wnd_size.0, c.wnd_size.1);

        // Ask server to allocate one
        if conv == 0 {
            kcp.input_conv();
        }

        kcp.update(now_millis())?;

        Ok(KcpSocket {
            kcp,
            last_update: Instant::now(),
            socket,
            flush_write: c.flush_write,
            flush_ack_input: c.flush_acks_input,
            sent_first: false,
            pending_sender: None,
            pending_receiver: None,
            closed: false,
        })
    }

    #[inline]
    pub fn mtu(&self) -> usize {
        self.kcp.mtu()
    }

    pub fn input(&mut self, buf: &[u8]) -> KcpResult<bool> {
        match self.kcp.input(buf) {
            Ok(..) => {}
            Err(KcpError::ConvInconsistent(expected, actual)) => {
                tracing::trace!("[INPUT] Conv expected={} actual={} ignored", expected, actual);
                return Ok(false);
            }
            Err(err) => return Err(err),
        }
        self.last_update = Instant::now();

        if self.flush_ack_input {
            self.kcp.flush_ack()?;
        }

        Ok(self.try_wake_pending_waker())
    }

    /// Call if you want to send some data
    pub fn poll_send(&mut self, cx: &mut Context<'_>, mut buf: &[u8]) -> Poll<KcpResult<usize>> {
        if self.closed {
            return Ok(0).into();
        }

        // If:
        //     1. Have sent the first packet (asking for conv)
        //     2. Too many pending packets
        if self.sent_first && (self.kcp.wait_snd() >= self.kcp.snd_wnd() as usize || self.kcp.waiting_conv()) {
            tracing::trace!(
                "[SEND] waitsnd={} sndwnd={} excceeded or waiting conv={}",
                self.kcp.wait_snd(),
                self.kcp.snd_wnd(),
                self.kcp.waiting_conv()
            );

            if let Some(waker) = self.pending_sender.replace(cx.waker().clone()) {
                if !cx.waker().will_wake(&waker) {
                    waker.wake();
                }
            }
            return Poll::Pending;
        }

        if !self.sent_first && self.kcp.waiting_conv() && buf.len() > self.kcp.mss() as usize {
            buf = &buf[..self.kcp.mss() as usize];
        }

        let n = self.kcp.send(buf)?;
        self.sent_first = true;
        self.last_update = Instant::now();

        if self.flush_write {
            self.kcp.flush()?;
        }

        Ok(n).into()
    }

    /// Call if you want to send some data
    #[allow(dead_code)]
    pub async fn send(&mut self, buf: &[u8]) -> KcpResult<usize> {
        future::poll_fn(|cx| self.poll_send(cx, buf)).await
    }

    #[allow(dead_code)]
    pub fn try_recv(&mut self, buf: &mut [u8]) -> KcpResult<usize> {
        if self.closed {
            return Ok(0);
        }
        self.kcp.recv(buf)
    }

    pub fn poll_recv(&mut self, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<KcpResult<usize>> {
        if self.closed {
            return Ok(0).into();
        }

        match self.kcp.recv(buf) {
            Ok(n) => Ok(n).into(),
            Err(KcpError::RecvQueueEmpty) => {
                if let Some(waker) = self.pending_receiver.replace(cx.waker().clone()) {
                    if !cx.waker().will_wake(&waker) {
                        waker.wake();
                    }
                }
                Poll::Pending
            }
            Err(err) => Err(err).into(),
        }
    }

    #[allow(dead_code)]
    pub async fn recv(&mut self, buf: &mut [u8]) -> KcpResult<usize> {
        future::poll_fn(|cx| self.poll_recv(cx, buf)).await
    }

    pub fn flush(&mut self) -> KcpResult<()> {
        self.kcp.flush()?;
        self.last_update = Instant::now();
        Ok(())
    }

    fn try_wake_pending_waker(&mut self) -> bool {
        let mut waked = false;

        if self.pending_sender.is_some()
            && self.kcp.wait_snd() < self.kcp.snd_wnd() as usize
            && !self.kcp.waiting_conv()
        {
            let waker = self.pending_sender.take().unwrap();
            waker.wake();

            waked = true;
        }

        if self.pending_receiver.is_some() {
            if let Ok(peek) = self.kcp.peeksize() {
                if peek > 0 {
                    let waker = self.pending_receiver.take().unwrap();
                    waker.wake();

                    waked = true;
                }
            }
        }

        waked
    }

    pub fn update(&mut self) -> KcpResult<Instant> {
        let now = now_millis();
        self.kcp.update(now)?;
        let next = self.kcp.check(now);

        self.try_wake_pending_waker();

        Ok(Instant::now() + Duration::from_millis(next as u64))
    }

    pub fn close(&mut self) {
        self.closed = true;
        if let Some(w) = self.pending_sender.take() {
            w.wake();
        }
        if let Some(w) = self.pending_receiver.take() {
            w.wake();
        }
    }

    pub fn udp_socket(&self) -> &Arc<UdpSocket> {
        &self.socket
    }

    pub fn can_close(&self) -> bool {
        self.kcp.wait_snd() == 0
    }

    pub fn conv(&self) -> u32 {
        self.kcp.conv()
    }

    pub fn set_conv(&mut self, conv: u32) {
        self.kcp.set_conv(conv);
    }

    pub fn waiting_conv(&self) -> bool {
        self.kcp.waiting_conv()
    }

    pub fn peek_size(&self) -> KcpResult<usize> {
        self.kcp.peeksize()
    }

    pub fn last_update_time(&self) -> Instant {
        self.last_update
    }
}

#[cfg(test)]
mod test {

    use std::net::SocketAddr;
    use std::sync::Arc;
    use tokio::{
        sync::Mutex,
        time::{self, Instant},
    };

    use super::super::kcp;
    use super::KcpConfig;
    use super::KcpError;
    use super::KcpSocket;
    use super::UdpSocket;

    #[tokio::test]
    #[traced_test]
    async fn kcp_echo() {
        static CONV: u32 = 0xdeadbeef;

        // s1 connects s2
        let s1 = UdpSocket::listen(&"127.0.0.1:0".parse::<SocketAddr>().unwrap())
            .await
            .unwrap();
        let s2 = UdpSocket::listen(&"127.0.0.1:0".parse::<SocketAddr>().unwrap())
            .await
            .unwrap();

        let s1_addr = s1.local_addr().unwrap();
        let s2_addr = s2.local_addr().unwrap();

        let s1 = Arc::new(s1);
        let s2 = Arc::new(s2);

        let config = KcpConfig::default();
        let kcp1 = KcpSocket::new(&config, 0, s1.clone(), s2_addr, true, None, None).unwrap();
        let kcp2 = KcpSocket::new(&config, CONV, s2.clone(), s1_addr, true, None, None).unwrap();

        let kcp1 = Arc::new(Mutex::new(kcp1));
        let kcp2 = Arc::new(Mutex::new(kcp2));

        let kcp1_task = {
            let kcp1 = kcp1.clone();
            tokio::spawn(async move {
                loop {
                    let mut kcp = kcp1.lock().await;
                    let next = kcp.update().expect("update");
                    tracing::trace!("kcp1 next tick {:?}", next);
                    time::sleep_until(Instant::from_std(next)).await;
                }
            }.in_current_span())
        };

        let kcp2_task = {
            let kcp2 = kcp2.clone();
            tokio::spawn(async move {
                loop {
                    let mut kcp = kcp2.lock().await;
                    let next = kcp.update().expect("update");
                    tracing::trace!("kcp2 next tick {:?}", next);
                    time::sleep_until(Instant::from_std(next)).await;
                }
            }.in_current_span())
        };

        const SEND_BUFFER: &[u8] = b"HELLO WORLD";

        {
            let n = kcp1.lock().await.send(SEND_BUFFER).await.unwrap();
            assert_eq!(n, SEND_BUFFER.len());
        }

        let echo_task = tokio::spawn(async move {
            let mut buf = [0u8; 1024];

            loop {
                let n = s2.recv(&mut buf).await.unwrap();

                let packet = &mut buf[..n];

                let conv = kcp::get_conv(packet);
                if conv == 0 {
                    kcp::set_conv(packet, CONV);
                }

                let mut kcp2 = kcp2.lock().await;
                kcp2.input(packet).unwrap();

                match kcp2.try_recv(&mut buf) {
                    Ok(n) => {
                        let received = &buf[..n];
                        kcp2.send(received).await.unwrap();
                    }
                    Err(KcpError::RecvQueueEmpty) => {
                        continue;
                    }
                    Err(err) => {
                        panic!("kcp.recv error: {:?}", err);
                    }
                }
            }
        }.in_current_span());

        {
            let mut buf = [0u8; 1024];

            loop {
                let n = s1.recv(&mut buf).await.unwrap();

                let packet = &buf[..n];

                let mut kcp1 = kcp1.lock().await;
                kcp1.input(packet).unwrap();

                match kcp1.try_recv(&mut buf) {
                    Ok(n) => {
                        let received = &buf[..n];
                        assert_eq!(received, SEND_BUFFER);
                        break;
                    }
                    Err(KcpError::RecvQueueEmpty) => {
                        continue;
                    }
                    Err(err) => {
                        panic!("kcp.recv error: {:?}", err);
                    }
                }
            }
        }

        echo_task.abort();
        kcp1_task.abort();
        kcp2_task.abort();
    }
}
