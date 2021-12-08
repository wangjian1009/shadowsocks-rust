use super::{Sniffer, SnifferChain, SnifferCheckError, SnifferProtocol};

pub struct SnifferChainNode<T: Sniffer, N> {
    sniffer: Option<T>,
    chain: Option<N>,
}

impl<T: Sniffer> SnifferChainNode<T, ()> {
    pub fn new(sniffer: T) -> SnifferChainNode<T, ()> {
        SnifferChainNode {
            sniffer: Some(sniffer),
            chain: None,
        }
    }

    pub fn join<T2: Sniffer>(self, sniffer: T2) -> SnifferChainNode<T2, Self> {
        SnifferChainNode {
            sniffer: Some(sniffer),
            chain: Some(self),
        }
    }
}

impl<T: Sniffer> SnifferChain for SnifferChainNode<T, ()> {
    fn check(&mut self, data: &[u8]) -> Result<SnifferProtocol, SnifferCheckError> {
        assert!(self.chain.is_none());

        match self.sniffer.as_mut() {
            None => Err(SnifferCheckError::Other("sniffer already checked!".to_string())),
            Some(sniffer) => match sniffer.check(data) {
                Ok(()) => {
                    self.sniffer = None;
                    Ok(T::PROTOCOL)
                }
                Err(SnifferCheckError::NoClue) => Err(SnifferCheckError::NoClue),
                Err(SnifferCheckError::Reject) => {
                    self.sniffer = None;
                    Err(SnifferCheckError::Reject)
                }
                Err(SnifferCheckError::Other(err)) => {
                    self.sniffer = None;
                    Err(SnifferCheckError::Other(err))
                }
            },
        }
    }
}

impl<T, N> SnifferChain for SnifferChainNode<T, N>
where
    T: Sniffer,
    N: SnifferChain,
{
    fn check(&mut self, data: &[u8]) -> Result<SnifferProtocol, SnifferCheckError> {
        if self.sniffer.is_none() && self.chain.is_none() {
            return Err(SnifferCheckError::Other("sniffer already checked!".to_owned()));
        }

        if let Some(next) = self.chain.as_mut() {
            match next.check(data) {
                Ok(r) => {
                    self.sniffer = None;
                    self.chain = None;
                    return Ok(r);
                }
                Err(SnifferCheckError::NoClue) => {}
                Err(SnifferCheckError::Reject) => {
                    self.chain = None;
                }
                Err(SnifferCheckError::Other(err)) => return Err(SnifferCheckError::Other(err)),
            }
        }

        if let Some(sniffer) = self.sniffer.as_mut() {
            match sniffer.check(data) {
                Ok(()) => {
                    self.sniffer = None;
                    self.chain = None;
                    return Ok(T::PROTOCOL);
                }
                Err(SnifferCheckError::NoClue) => {}
                Err(SnifferCheckError::Reject) => {
                    self.sniffer = None;
                }
                Err(SnifferCheckError::Other(err)) => return Err(SnifferCheckError::Other(err)),
            }
        }

        if self.sniffer.is_none() && self.chain.is_none() {
            return Err(SnifferCheckError::Reject);
        } else {
            return Err(SnifferCheckError::NoClue);
        }
    }
}

impl<T, N> SnifferChainNode<T, N>
where
    T: Sniffer,
    N: SnifferChain,
{
    pub fn join<T2: Sniffer>(self, sniffer: T2) -> SnifferChainNode<T2, Self> {
        SnifferChainNode {
            sniffer: Some(sniffer),
            chain: Some(self),
        }
    }
}

#[cfg(test)]
mod test {
    use super::super::*;
    use mockall::*;

    mock! {
        pub SnifferBittorrent {}
        impl Sniffer for SnifferBittorrent {
            const PROTOCOL: SnifferProtocol = SnifferProtocol::Bittorrent;
            fn check(&mut self, data: &[u8]) -> Result<(), SnifferCheckError>;
        }
    }

    mock! {
        pub SnifferHttp {}
        impl Sniffer for SnifferHttp {
            const PROTOCOL: SnifferProtocol = SnifferProtocol::Http;
            fn check(&mut self, data: &[u8]) -> Result<(), SnifferCheckError>;
        }
    }

    #[test]
    fn single_reject() {
        let mut sniffer1 = MockSnifferBittorrent::new();
        sniffer1
            .expect_check()
            .times(1)
            .returning(|_x| Err(SnifferCheckError::NoClue));
        sniffer1
            .expect_check()
            .times(1)
            .returning(|_x| Err(SnifferCheckError::Reject));
        let mut chain = SnifferChainNode::new(sniffer1);

        assert_eq!(chain.check(&[]), Err(SnifferCheckError::NoClue));
        assert_eq!(chain.check(&[]), Err(SnifferCheckError::Reject));
        assert_eq!(
            chain.check(&[]),
            Err(SnifferCheckError::Other("sniffer already checked!".to_string()))
        );
    }

    #[test]
    fn single_accept() {
        let mut sniffer1 = MockSnifferBittorrent::new();
        sniffer1.expect_check().times(1).returning(|_x| Ok(()));
        let mut chain = SnifferChainNode::new(sniffer1);

        assert_eq!(chain.check(&[]), Ok(SnifferProtocol::Bittorrent));
        assert_eq!(
            chain.check(&[]),
            Err(SnifferCheckError::Other("sniffer already checked!".to_string()))
        );
    }

    #[test]
    fn single_error() {
        let mut sniffer1 = MockSnifferBittorrent::new();
        sniffer1
            .expect_check()
            .times(1)
            .returning(|_x| Err(SnifferCheckError::Other("test error".to_string())));
        let mut chain = SnifferChainNode::new(sniffer1);

        assert_eq!(
            chain.check(&[]),
            Err(SnifferCheckError::Other("test error".to_string()))
        );
        assert_eq!(
            chain.check(&[]),
            Err(SnifferCheckError::Other("sniffer already checked!".to_string()))
        );
    }

    #[test]
    fn multi_1pass() {
        let mut sniffer_bt = MockSnifferBittorrent::new();
        sniffer_bt.expect_check().times(1).returning(|_x| Ok(()));
        let sniffer_http = MockSnifferHttp::new();
        let mut chain = SnifferChainNode::new(sniffer_bt).join(sniffer_http);

        assert_eq!(chain.check(&[]), Ok(SnifferProtocol::Bittorrent));
        assert_eq!(
            chain.check(&[]),
            Err(SnifferCheckError::Other("sniffer already checked!".to_string()))
        );
    }

    #[test]
    fn multi_1error() {
        let mut sniffer_bt = MockSnifferBittorrent::new();
        sniffer_bt
            .expect_check()
            .times(1)
            .returning(|_x| Err(SnifferCheckError::Other("test error".to_string())));
        let sniffer_http = MockSnifferHttp::new();
        let mut chain = SnifferChainNode::new(sniffer_bt).join(sniffer_http);

        assert_eq!(
            chain.check(&[]),
            Err(SnifferCheckError::Other("test error".to_string()))
        );
        assert_eq!(
            chain.check(&[]),
            Err(SnifferCheckError::Other("sniffer already checked!".to_string()))
        );
    }

    #[test]
    fn multi_1noclue_2pass() {
        let mut sniffer_bt = MockSnifferBittorrent::new();
        sniffer_bt
            .expect_check()
            .times(1)
            .returning(|_x| Err(SnifferCheckError::NoClue));
        let mut sniffer_http = MockSnifferHttp::new();
        sniffer_http.expect_check().times(1).returning(|_x| Ok(()));
        let mut chain = SnifferChainNode::new(sniffer_bt).join(sniffer_http);

        assert_eq!(chain.check(&[]), Ok(SnifferProtocol::Http));
        assert_eq!(
            chain.check(&[]),
            Err(SnifferCheckError::Other("sniffer already checked!".to_string()))
        );
    }

    #[test]
    fn multi_reject() {
        let mut sniffer_bt = MockSnifferBittorrent::new();
        sniffer_bt
            .expect_check()
            .times(1)
            .returning(|_x| Err(SnifferCheckError::NoClue));
        sniffer_bt
            .expect_check()
            .times(1)
            .returning(|_x| Err(SnifferCheckError::Reject));
        let mut sniffer_http = MockSnifferHttp::new();
        sniffer_http
            .expect_check()
            .times(2)
            .returning(|_x| Err(SnifferCheckError::NoClue));
        sniffer_http
            .expect_check()
            .times(1)
            .returning(|_x| Err(SnifferCheckError::Reject));
        let mut chain = SnifferChainNode::new(sniffer_bt).join(sniffer_http);

        assert_eq!(chain.check(&[]), Err(SnifferCheckError::NoClue));
        assert_eq!(chain.check(&[]), Err(SnifferCheckError::NoClue));
        assert_eq!(chain.check(&[]), Err(SnifferCheckError::Reject));
        assert_eq!(
            chain.check(&[]),
            Err(SnifferCheckError::Other("sniffer already checked!".to_string()))
        );
    }
}
