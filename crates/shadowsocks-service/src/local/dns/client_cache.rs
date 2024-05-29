//! DNS Client cache

#[cfg(unix)]
use std::path::Path;
use std::{
    collections::{hash_map::Entry, HashMap, VecDeque},
    io,
    net::SocketAddr,
    time::Duration,
};

use hickory_resolver::proto::{error::ProtoError, op::Message};
use tokio::sync::Mutex;
use tracing::{debug, trace};

use shadowsocks::{canceler::Canceler, net::ConnectOpts, relay::socks5::Address};

use crate::local::{context::ServiceContext, loadbalancing::ServerIdent};

use super::upstream::DnsClient;

#[derive(Clone, Debug, Hash, Eq, PartialEq, PartialOrd, Ord)]
enum DnsClientKey {
    TcpLocal(SocketAddr),
    UdpLocal(SocketAddr),
    TcpRemote(Address),
    UdpRemote(Address),
}

pub struct DnsClientCache {
    cache: Mutex<HashMap<DnsClientKey, VecDeque<DnsClient>>>,
    timeout: Duration,
    retry_count: usize,
    max_client_per_addr: usize,
}

impl DnsClientCache {
    pub fn new(max_client_per_addr: usize) -> DnsClientCache {
        DnsClientCache {
            cache: Mutex::new(HashMap::new()),
            timeout: Duration::from_secs(5),
            retry_count: 1,
            max_client_per_addr,
        }
    }

    pub async fn lookup_local(
        &self,
        ns: SocketAddr,
        msg: Message,
        connect_opts: &ConnectOpts,
        is_udp: bool,
        canceler: &Canceler,
    ) -> Result<Message, ProtoError> {
        let key = match is_udp {
            true => DnsClientKey::UdpLocal(ns),
            false => DnsClientKey::TcpLocal(ns),
        };
        self.lookup_dns(&key, msg, connect_opts, None, None, canceler).await
    }

    pub async fn lookup_remote(
        &self,
        context: &ServiceContext,
        svr: &ServerIdent,
        ns: &Address,
        msg: Message,
        is_udp: bool,
        canceler: &Canceler,
    ) -> Result<Message, ProtoError> {
        let key = match is_udp {
            true => DnsClientKey::UdpRemote(ns.clone()),
            false => DnsClientKey::TcpRemote(ns.clone()),
        };

        self.lookup_dns(
            &key,
            msg,
            context.connect_opts_ref(),
            Some(context),
            Some(svr),
            canceler,
        )
        .await
    }

    #[cfg(unix)]
    pub async fn lookup_unix_stream<P: AsRef<Path>>(
        &self,
        ns: &P,
        msg: Message,
        canceler: &Canceler,
    ) -> Result<Message, ProtoError> {
        let mut last_err = None;

        for _ in 0..self.retry_count {
            // UNIX stream won't keep connection alive
            //
            // https://github.com/shadowsocks/shadowsocks-rust/pull/567
            //
            // 1. The cost of recreating UNIX stream sockets are very low
            // 2. This feature is only used by shadowsocks-android, and it doesn't support connection reuse
            if canceler.is_canceled() {
                return Err(io::Error::new(io::ErrorKind::Other, "canceled").into());
            }

            let mut client = match DnsClient::connect_unix_stream(ns, canceler).await {
                Ok(client) => client,
                Err(err) => {
                    last_err = Some(From::from(err));
                    continue;
                }
            };

            let res = match client.lookup_timeout(msg.clone(), self.timeout).await {
                Ok(msg) => msg,
                Err(error) => {
                    last_err = Some(error);
                    continue;
                }
            };
            return Ok(res);
        }
        Err(last_err.unwrap())
    }

    async fn lookup_dns(
        &self,
        dck: &DnsClientKey,
        msg: Message,
        connect_opts: &ConnectOpts,
        context: Option<&ServiceContext>,
        svr: Option<&ServerIdent>,
        canceler: &Canceler,
    ) -> Result<Message, ProtoError> {
        let mut last_err = None;
        for _ in 0..self.retry_count {
            if canceler.is_canceled() {
                return Err(io::Error::new(io::ErrorKind::Other, "canceled").into());
            }

            let mut client = self.get_client(dck).await;
            if client.is_none() {
                trace!("creating connection to DNS server {:?}", dck);

                let create_result = match dck {
                    DnsClientKey::TcpLocal(tcp_l) => DnsClient::connect_tcp_local(*tcp_l, connect_opts, canceler).await,
                    DnsClientKey::UdpLocal(udp_l) => DnsClient::connect_udp_local(*udp_l, connect_opts, canceler).await,
                    DnsClientKey::TcpRemote(tcp_l) => {
                        let context = match context {
                            Some(context) => context,
                            None => {
                                return Err(io::Error::new(io::ErrorKind::Other, "connect remote no context").into());
                            }
                        };

                        let svr = match svr {
                            Some(svr) => svr,
                            None => {
                                return Err(io::Error::new(io::ErrorKind::Other, "connect remote no svr").into());
                            }
                        };

                        DnsClient::connect_tcp_remote(context, svr, tcp_l, canceler).await
                    }
                    DnsClientKey::UdpRemote(udp_l) => {
                        let context = match context {
                            Some(context) => context,
                            None => {
                                return Err(io::Error::new(io::ErrorKind::Other, "connect remote no context").into());
                            }
                        };

                        let svr = match svr {
                            Some(svr) => svr,
                            None => {
                                return Err(io::Error::new(io::ErrorKind::Other, "connect remote no svr").into());
                            }
                        };

                        DnsClient::connect_udp_remote(
                            context.context(),
                            svr,
                            udp_l.clone(),
                            context.connect_opts_ref(),
                            context.flow_stat(),
                            canceler,
                        )
                        .await
                    }
                };

                match create_result {
                    Ok(c) => client = Some(c),
                    Err(err) => {
                        last_err = Some(From::from(err));
                        continue;
                    }
                }
            } else {
                trace!("reuse connection to DNS server {:?}", dck);
            }

            let mut client = client.unwrap();

            let mut waiter = canceler.waiter();
            tokio::select! {
                r = client.lookup_timeout(msg.clone(), self.timeout) => {
                    match r {
                        Ok(msg) => {
                            self.save_client(dck.clone(), client).await;
                            return Ok(msg);
                        }
                        Err(err) => {
                            last_err = Some(err);
                            continue;
                        }
                    }
                }
                _ = waiter.wait() => {
                    trace!("lookup canceled");
                    return Err(io::Error::new(io::ErrorKind::Other, "canceled").into());
                }
            }
        }
        Err(last_err.unwrap())
    }

    async fn get_client(&self, key: &DnsClientKey) -> Option<DnsClient> {
        // Check if there already is a cached client
        if let Some(q) = self.cache.lock().await.get_mut(key) {
            while let Some(c) = q.pop_front() {
                if !c.check_connected().await {
                    debug!("cached DNS client for {:?} is lost", key);
                    continue;
                }
                return Some(c);
            }
        }
        None
    }

    async fn save_client(&self, key: DnsClientKey, client: DnsClient) {
        match self.cache.lock().await.entry(key) {
            Entry::Occupied(occ) => {
                let q = occ.into_mut();
                q.push_back(client);
                if q.len() > self.max_client_per_addr {
                    q.pop_front();
                }
            }
            Entry::Vacant(vac) => {
                let mut q = VecDeque::with_capacity(self.max_client_per_addr);
                q.push_back(client);
                vac.insert(q);
            }
        }
    }
}
