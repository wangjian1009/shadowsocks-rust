use std::{
    io::{self, IoSlice},
    pin::Pin,
    sync::Arc,
    task::{self, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::{SnifferChain, SnifferCheckError, SnifferProtocol};

#[derive(Clone, Copy, PartialEq, Debug)]
enum State {
    Init,
    Checking,
    Checked,
}

pub struct SnifferStream<S, C: SnifferChain> {
    stream: S,
    state: State,
    buf: Option<Arc<Vec<u8>>>,
    checker: Option<Arc<C>>,
    protocol: Option<SnifferProtocol>,
}

impl<S, C: SnifferChain> SnifferStream<S, C> {
    #[inline]
    pub fn from_stream(stream: S, checker: C) -> SnifferStream<S, C> {
        SnifferStream {
            stream,
            state: State::Init,
            buf: None,
            protocol: None,
            checker: Some(Arc::new(checker)),
        }
    }

    #[cfg(test)]
    #[inline]
    fn state(&self) -> State {
        self.state
    }

    #[inline]
    pub fn protocol(&self) -> &Option<SnifferProtocol> {
        &self.protocol
    }

    #[inline]
    fn check_sniffer(&mut self, data: &[u8]) -> Result<SnifferProtocol, SnifferCheckError> {
        let mut arc_checker = self.checker.clone().unwrap();
        self.checker = None;

        let checker = Arc::get_mut(&mut arc_checker).unwrap();
        let r = checker.check(data);
        self.checker = Some(arc_checker);
        r
    }
}

impl<S, C: SnifferChain> AsyncRead for SnifferStream<S, C>
where
    S: AsyncRead + Unpin,
{
    // 协议检测在没有确定以前缓存数据等待不返回，一旦确定（或者确定不匹配任何协议），则尽快返回数据
    #[inline]
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        loop {
            match &self.state {
                State::Init => {
                    match Pin::new(&mut self.stream).poll_read(cx, buf) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(r) => match r {
                            Ok(..) => {}
                            Err(e) => return Poll::Ready(Err(e)),
                        },
                    }

                    if buf.filled().is_empty() {
                        // 没有开始检测，没有任何底层数据，直接返回
                        self.state = State::Checked;
                        self.checker = None;
                        return Poll::Ready(Ok(()));
                    }

                    match self.check_sniffer(buf.filled()) {
                        Ok(r) => {
                            // 直接检查完成，不需要缓冲数据，直接返回所取到的数据就可以了
                            self.protocol = Some(r);
                            self.state = State::Checked;
                            self.checker = None;
                            return Poll::Ready(Ok(()));
                        }
                        Err(SnifferCheckError::NoClue) => {
                            // 需要更多数据，则缓冲数据，等待更多数据达到
                            self.buf = Some(Arc::new(buf.filled().to_owned()));
                            buf.clear();
                            self.state = State::Checking;
                            continue;
                        }
                        Err(SnifferCheckError::Reject) => {
                            // 检测没有通过，也无需等待更多数据检测
                            self.state = State::Checked;
                            self.checker = None;
                            return Poll::Ready(Ok(()));
                        }
                        Err(SnifferCheckError::Other(err)) => {
                            // 检测发生错误，则返回错误
                            return Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, err)));
                        }
                    }
                }
                State::Checking => {
                    match Pin::new(&mut self.stream).poll_read(cx, buf) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(r) => match r {
                            Ok(..) => {}
                            Err(e) => return Poll::Ready(Err(e)),
                        },
                    }

                    if buf.filled().is_empty() {
                        // 检测过程中，底层流数据已经取完，则将缓冲数据返回
                        self.state = State::Checked;
                        self.checker = None;
                        continue;
                    }

                    // 将新获取的数据合并到缓冲的数据进行检测
                    let mut arc_combine_buf = self.buf.clone().unwrap();
                    self.buf = None;

                    let combine_buf = Arc::get_mut(&mut arc_combine_buf).unwrap();
                    combine_buf.append(&mut buf.filled().to_owned());
                    buf.clear();

                    match self.check_sniffer(&combine_buf[..]) {
                        Ok(r) => {
                            // 检测通过，进入已经检测状态，缓冲数据在Checked状态中，根据传入的capacity逐次取走
                            self.protocol = Some(r);
                            self.buf = Some(arc_combine_buf);
                            self.state = State::Checked;
                            self.checker = None;
                            continue;
                        }
                        Err(SnifferCheckError::NoClue) => {
                            // 检测数据不足，继续缓冲数据等待
                            self.buf = Some(arc_combine_buf);
                            continue;
                        }
                        Err(SnifferCheckError::Reject) => {
                            self.buf = Some(arc_combine_buf);
                            self.state = State::Checked;
                            self.checker = None;
                            continue;
                        }
                        Err(SnifferCheckError::Other(err)) => {
                            // 检测发生错误，则返回错误
                            return Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, err)));
                        }
                    }
                }
                State::Checked => {
                    // 有缓冲数据则首先返回缓冲数据
                    if let Some(combine_buf) = self.buf.as_mut() {
                        if combine_buf.len() <= buf.capacity() {
                            buf.put_slice(&combine_buf[..]);
                            self.buf = None;
                            return Poll::Ready(Ok(()));
                        } else {
                            buf.put_slice(&combine_buf[..buf.capacity()]);
                            Arc::get_mut(combine_buf).unwrap().remove(buf.filled().len());
                            return Poll::Ready(Ok(()));
                        }
                    }

                    // 直接调用底层的pull
                    return Pin::new(&mut self.stream).poll_read(cx, buf);
                }
            }
        }
    }
}

impl<S, C: SnifferChain> AsyncWrite for SnifferStream<S, C>
where
    S: AsyncWrite + Unpin,
{
    #[inline]
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let stream = Pin::new(&mut self.stream);
        stream.poll_write(cx, buf)
    }

    #[inline]
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        let stream = Pin::new(&mut self.stream);
        stream.poll_flush(cx)
    }

    #[inline]
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> Poll<io::Result<()>> {
        let stream = Pin::new(&mut self.stream);
        stream.poll_shutdown(cx)
    }

    #[inline]
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let stream = Pin::new(&mut self.stream);
        stream.poll_write_vectored(cx, bufs)
    }
}

#[cfg(test)]
mod test {
    use super::{super::*, *};
    use mockall::{predicate::*, *};
    use tokio_test::io::Builder;
    use tokio_util::io::read_buf;

    use super::SnifferStream;

    mock! {
        pub SnifferChain {}
        impl SnifferChain for SnifferChain {
            fn check(&mut self, data: &[u8]) -> Result<SnifferProtocol, SnifferCheckError>;
        }
    }

    #[tokio::test]
    async fn init_eof() {
        let input = Builder::new().build();

        let checker = MockSnifferChain::new();

        let mut s = SnifferStream::from_stream(input, checker);
        let (read_count, output_buf) = read_buf_all(&mut s).await.unwrap();

        assert_eq!(1, read_count);
        assert_eq!("".as_bytes(), &output_buf[..]);
        assert_eq!(State::Checked, s.state());
        assert_eq!(&None, s.protocol());
    }

    #[tokio::test]
    async fn init_reject() {
        let input = Builder::new().read("a".as_bytes()).build();

        let mut checker = MockSnifferChain::new();
        checker
            .expect_check()
            .times(1)
            .returning(|_x| Err(SnifferCheckError::Reject));

        let mut s = SnifferStream::from_stream(input, checker);
        let (read_count, output_buf) = read_buf_all(&mut s).await.unwrap();

        assert_eq!(2, read_count);
        assert_eq!("a".as_bytes(), &output_buf[..]);
        assert_eq!(State::Checked, s.state());
    }

    #[tokio::test]
    async fn init_done() {
        let input = Builder::new().read("a".as_bytes()).build();

        let mut checker = MockSnifferChain::new();
        checker
            .expect_check()
            .times(1)
            .returning(|_x| Ok(SnifferProtocol::Bittorrent));

        let s = SnifferStream::from_stream(input, checker);
        tokio::pin!(s);

        let mut output_buf = Vec::<u8>::new();
        let readed_size = read_buf(&mut s, &mut output_buf).await.unwrap();

        assert_eq!(1, readed_size);
        assert_eq!("a".as_bytes(), &output_buf[..]);
        assert_eq!(State::Checked, s.state());
        assert_eq!(&Some(SnifferProtocol::Bittorrent), s.protocol());
    }

    #[tokio::test]
    async fn checking_eof() {
        let input = Builder::new().read("a".as_bytes()).build();

        let mut checker = MockSnifferChain::new();
        checker
            .expect_check()
            .times(1)
            .returning(|_x| Err(SnifferCheckError::NoClue));

        let mut s = SnifferStream::from_stream(input, checker);
        let (read_count, output_buf) = read_buf_all(&mut s).await.unwrap();

        assert_eq!(2, read_count);
        assert_eq!("a".as_bytes(), &output_buf[..]);
        assert_eq!(State::Checked, s.state());
        assert_eq!(&None, s.protocol());
    }

    #[tokio::test]
    async fn checking_reject() {
        let input = Builder::new().read("a".as_bytes()).read("b".as_bytes()).build();

        let mut checker = MockSnifferChain::new();
        checker
            .expect_check()
            .times(1)
            .returning(|_x| Err(SnifferCheckError::NoClue));
        checker
            .expect_check()
            .times(1)
            .returning(|_x| Err(SnifferCheckError::Reject));

        let mut s = SnifferStream::from_stream(input, checker);
        let (read_count, output_buf) = read_buf_all(&mut s).await.unwrap();

        assert_eq!(2, read_count);
        assert_eq!("ab".as_bytes(), &output_buf[..]);
        assert_eq!(State::Checked, s.state());
        assert_eq!(&None, s.protocol());
    }

    #[tokio::test]
    async fn checked_pass_data() {
        let input = Builder::new()
            .read("a".as_bytes())
            .read("b".as_bytes())
            .read("c".as_bytes())
            .build();

        let mut checker = MockSnifferChain::new();
        checker
            .expect_check()
            .with(eq("a".as_bytes()))
            .times(1)
            .returning(|_x| Err(SnifferCheckError::NoClue));
        checker
            .expect_check()
            .with(eq("ab".as_bytes()))
            .times(1)
            .returning(|_x| Ok(SnifferProtocol::Bittorrent));

        let s = SnifferStream::from_stream(input, checker);
        tokio::pin!(s);

        let mut output_buf = Vec::<u8>::new();
        read_buf(&mut s, &mut output_buf).await.unwrap();
        assert_eq!("ab".as_bytes(), &output_buf[..]);
        assert_eq!(State::Checked, s.state());
        assert_eq!(&Some(SnifferProtocol::Bittorrent), s.protocol());

        assert_eq!(1, read_buf(&mut s, &mut output_buf).await.unwrap());
        assert_eq!("abc".as_bytes(), &output_buf[..]);

        assert_eq!(0, read_buf(&mut s, &mut output_buf).await.unwrap());
    }

    #[tokio::test]
    async fn checked_reject_data() {
        let input = Builder::new()
            .read("a".as_bytes())
            .read("b".as_bytes())
            .read("c".as_bytes())
            .build();

        let mut checker = MockSnifferChain::new();
        checker
            .expect_check()
            .with(eq("a".as_bytes()))
            .times(1)
            .returning(|_x| Err(SnifferCheckError::NoClue));
        checker
            .expect_check()
            .with(eq("ab".as_bytes()))
            .times(1)
            .returning(|_x| Err(SnifferCheckError::Reject));

        let mut s = SnifferStream::from_stream(input, checker);
        let (read_count, output_buf) = read_buf_all(&mut s).await.unwrap();

        assert_eq!(3, read_count);
        assert_eq!("abc".as_bytes(), &output_buf[..]);
        assert_eq!(State::Checked, s.state());
        assert_eq!(&None, s.protocol());
    }

    async fn read_buf_all<S: AsyncRead + Unpin>(s: &mut S) -> io::Result<(usize, Vec<u8>)> {
        tokio::pin!(s);

        let mut output_buf = Vec::<u8>::new();
        let mut reads = 0;
        loop {
            reads += 1;
            let n = read_buf(&mut s, &mut output_buf).await?;

            if n == 0 {
                break;
            }
        }
        Ok((reads, output_buf))
    }
}
