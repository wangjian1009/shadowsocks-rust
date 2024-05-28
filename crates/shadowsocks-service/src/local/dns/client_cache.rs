//! DNS Client cache

#[cfg(unix)]
use std::path::Path;
use std::{
    collections::{hash_map::Entry, HashMap, VecDeque},
    net::SocketAddr,
    time::Duration,
};

use hickory_resolver::proto::{error::ProtoError, op::Message};
use tokio::sync::Mutex;
use tracing::{debug, trace};

use shadowsocks::{net::ConnectOpts, relay::socks5::Address};

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
    ) -> Result<Message, ProtoError> {
        let key = match is_udp {
            true => DnsClientKey::UdpLocal(ns),
            false => DnsClientKey::TcpLocal(ns),
        };
        self.lookup_dns(&key, msg, connect_opts, None, None).await
    }

    pub async fn lookup_remote(
        &self,
        context: &ServiceContext,
        svr: &ServerIdent,
        ns: &Address,
        msg: Message,
        is_udp: bool,
    ) -> Result<Message, ProtoError> {
        let key = match is_udp {
            true => DnsClientKey::UdpRemote(ns.clone()),
            false => DnsClientKey::TcpRemote(ns.clone()),
        };

        self.lookup_dns(&key, msg, context.connect_opts_ref(), Some(context), Some(svr))
            .await
    }

    #[cfg(unix)]
    pub async fn lookup_unix_stream<P: AsRef<Path>>(&self, ns: &P, msg: Message) -> Result<Message, ProtoError> {
        let mut last_err = None;

        for _ in 0..self.retry_count {
            // UNIX stream won't keep connection alive
            //
            // https://github.com/shadowsocks/shadowsocks-rust/pull/567
            //
            // 1. The cost of recreating UNIX stream sockets are very low
            // 2. This feature is only used by shadowsocks-android, and it doesn't support connection reuse

            let mut client = match DnsClient::connect_unix_stream(ns).await {
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
    ) -> Result<Message, ProtoError> {
        let mut last_err = None;
        for _ in 0..self.retry_count {
            let mut client = self.get_client(dck).await;
            if client.is_none() {
                trace!("creating connection to DNS server {:?}", dck);

                let create_result = match dck {
                    DnsClientKey::TcpLocal(tcp_l) => DnsClient::connect_tcp_local(*tcp_l, connect_opts).await,
                    DnsClientKey::UdpLocal(udp_l) => DnsClient::connect_udp_local(*udp_l, connect_opts).await,
                    DnsClientKey::TcpRemote(tcp_l) => {
                        DnsClient::connect_tcp_remote(
                            &context.unwrap().context(),
                            svr.unwrap(),
                            tcp_l,
                            context.unwrap().connect_opts_ref(),
                            context.unwrap().flow_stat(),
                            context.unwrap().connection_close_notify(),
                        )
                        .await
                    }
                    DnsClientKey::UdpRemote(udp_l) => {
                        DnsClient::connect_udp_remote(
                            context.unwrap().context(),
                            svr.unwrap(),
                            udp_l.clone(),
                            context.unwrap().connect_opts_ref(),
                            context.unwrap().flow_stat(),
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
            }
            else {
                trace!("reuse connection to DNS server {:?}", dck);
            }
            
            let mut client = client.unwrap();

            match client.lookup_timeout(msg.clone(), self.timeout).await {
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
