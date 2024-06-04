use std::{io, net::SocketAddr};
use tracing::{error, info_span, trace, warn, Instrument};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use byteorder::{BigEndian, ByteOrder};
use bytes::{BufMut, BytesMut};

use trust_dns_resolver::proto::{
    op::{header::MessageType, response_code::ResponseCode, Message, OpCode},
    rr::{rdata, RData, Record, RecordType},
};

use shadowsocks::{canceler::Canceler, dns_resolver::DnsResolver, timeout::TimeoutTicker};

pub async fn run_dns_tcp_stream<'a, I: AsyncRead + Unpin, O: AsyncWrite + Unpin>(
    dns_resolver: &'a DnsResolver,
    input: &'a mut I,
    output: &'a mut O,
    timeout_ticker: Option<TimeoutTicker>,
    canceler: &Canceler,
) -> io::Result<()> {
    let mut length_buf = [0u8; 2];
    let mut message_buf = BytesMut::new();
    loop {
        match input.read_exact(&mut length_buf).await {
            Ok(..) => {
                if let Some(o) = timeout_ticker.as_ref() {
                    o.tick();
                }
            }
            Err(ref err) if err.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(err) => {
                error!(error = ?err, "read length failed");
                return Err(err);
            }
        }

        let length = BigEndian::read_u16(&length_buf) as usize;

        message_buf.clear();
        message_buf.reserve(length);
        unsafe {
            message_buf.advance_mut(length);
        }

        match input.read_exact(&mut message_buf).await {
            Ok(..) => {}
            Err(err) => {
                error!(error = ?err, "read message failed");
                return Err(err);
            }
        }

        let request = match Message::from_vec(&message_buf) {
            Ok(m) => m,
            Err(err) => {
                error!(error = ?err, "parse message failed");
                return Err(err.into());
            }
        };

        let response = resolve(dns_resolver, request, canceler).await;

        let mut buf = response.to_vec()?;
        let length = buf.len();
        buf.resize(length + 2, 0);
        buf.copy_within(..length, 2);
        BigEndian::write_u16(&mut buf[..2], length as u16);

        match output.write_all(&buf).await {
            Ok(..) => {}
            Err(err) => {
                error!(error = ?err, "write response error");
                return Err(err);
            }
        }
    }

    Ok(())
}

pub async fn process_dns_udp_request(
    dns_resolver: &DnsResolver,
    input: &[u8],
    canceler: &Canceler,
) -> io::Result<Vec<u8>> {
    let request = match Message::from_vec(input) {
        Ok(m) => m,
        Err(err) => {
            error!(error = ?err, "parse message failed");
            return Err(err.into());
        }
    };

    let response = resolve(dns_resolver, request, canceler).await;
    match response.to_vec() {
        Ok(r) => {
            tracing::trace!("process complete");
            Ok(r)
        }
        Err(err) => Err(io::Error::new(io::ErrorKind::Other, err)),
    }
}

const DEFAULT_TTL: u32 = 300u32;

async fn resolve(dns_resolver: &DnsResolver, request: Message, canceler: &Canceler) -> Message {
    let mut response = Message::new();

    response
        .set_id(request.id())
        .set_recursion_desired(true)
        .set_recursion_available(true)
        .set_message_type(MessageType::Response);

    if !request.recursion_desired() {
        // RD is required by default. Otherwise it may not get valid respond from remote servers

        response.set_recursion_desired(false);
        response.set_response_code(ResponseCode::NotImp);
    } else if request.op_code() != OpCode::Query || request.message_type() != MessageType::Query {
        // Other ops are not supported

        response.set_response_code(ResponseCode::NotImp);
    } else if request.query_count() > 0 {
        for query in request.queries().iter() {
            response.add_query(query.clone());

            let span = info_span!("dns.query", query = query.to_string());
            response = async move {
                match dns_resolver
                    .resolve(query.name().to_string().as_str(), 0, canceler)
                    .await
                {
                    Ok(response_record_it) => {
                        let mut count = 0;
                        for addr in response_record_it {
                            let record = match addr {
                                SocketAddr::V4(addr) => {
                                    if query.query_type() != RecordType::A {
                                        continue;
                                    }
                                    let mut record = Record::with(query.name().clone(), RecordType::A, DEFAULT_TTL);
                                    record.set_data(Some(RData::A(rdata::A(*addr.ip()))));
                                    record
                                }
                                SocketAddr::V6(addr) => {
                                    if query.query_type() != RecordType::AAAA {
                                        continue;
                                    }
                                    let mut record = Record::with(query.name().clone(), RecordType::AAAA, DEFAULT_TTL);
                                    record.set_data(Some(RData::AAAA(rdata::AAAA(*addr.ip()))));
                                    record
                                }
                            };

                            count += 1;
                            trace!(answer = ?record.data().unwrap());
                            response.add_answer(record);
                        }

                        if count == 0 {
                            trace!("no answer(filted)");
                        }
                    }
                    Err(err) => {
                        warn!(error = ?err, "dns resolve error");
                        response.set_response_code(ResponseCode::ServFail);
                    }
                }
                response
            }
            .instrument(span)
            .await;
        }
    }

    response
}

#[cfg(test)]
mod test {
    use super::*;
    use async_trait::async_trait;
    use mockall::*;
    use shadowsocks::{canceler::CancelWaiter, dns_resolver::DnsResolve};
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr},
        str::FromStr,
    };
    use tokio::io::{BufReader, BufWriter};
    use trust_dns_resolver::proto::{op::Query, rr::Name};

    mock! {
        DnsResolve {}

        #[async_trait]
        impl DnsResolve for DnsResolve {
            async fn resolve(&self, addr: &str, port: u16) -> io::Result<Vec<SocketAddr>>;
        }
    }

    #[tokio::test]
    async fn tcp_query_basic() {
        let mut mock_resolve = MockDnsResolve::new();
        mock_resolve.expect_resolve().times(1).returning(|_addr, port| {
            Ok(["1.1.1.1", "1.1.1.2", "::1"]
                .iter()
                .map(|s| s.parse::<IpAddr>().unwrap())
                .map(|ip| SocketAddr::new(ip, port))
                .collect())
        });
        let resolver = DnsResolver::Custom(Box::new(mock_resolve));

        let response = tcp_process_query(
            &resolver,
            Message::new()
                .set_id(123)
                .set_recursion_desired(true)
                .set_recursion_available(true)
                .set_message_type(MessageType::Query)
                .add_query(Query::query(Name::from_str("www.baidu.com").unwrap(), RecordType::A)),
        )
        .await
        .unwrap();

        assert_eq!(2, response.answer_count());

        assert_eq!(
            Some(&RData::A(rdata::A(Ipv4Addr::new(1, 1, 1, 1)))),
            response.answers()[0].data()
        );
    }

    async fn tcp_process_query(resolver: &DnsResolver, request: &Message) -> io::Result<Message> {
        let mut request_buf = request.to_vec()?;
        let length = request_buf.len();
        request_buf.resize(length + 2, 0);
        request_buf.copy_within(..length, 2);
        BigEndian::write_u16(&mut request_buf[..2], length as u16);

        let mut output_buf = Vec::<u8>::new();
        let mut input = BufReader::new(&request_buf[..]);
        let mut output = BufWriter::new(&mut output_buf);
        run_dns_tcp_stream(resolver, &mut input, &mut output, None)
            .await
            .unwrap();
        output.flush().await?;

        let output_length = BigEndian::read_u16(&output_buf[..2]) as usize;
        assert_eq!(output_length + 2, output_buf.len());

        match Message::from_vec(&output_buf[2..]) {
            Ok(response) => Ok(response),
            Err(err) => Err(io::Error::new(io::ErrorKind::Other, err)),
        }
    }

    #[tokio::test]
    async fn udp_query_basic() {
        let mut mock_resolve = MockDnsResolve::new();
        mock_resolve.expect_resolve().times(1).returning(|_addr, port| {
            Ok(["1.1.1.1", "1.1.1.2", "::1"]
                .iter()
                .map(|s| s.parse::<IpAddr>().unwrap())
                .map(|ip| SocketAddr::new(ip, port))
                .collect())
        });
        let resolver = DnsResolver::Custom(Box::new(mock_resolve));
        let canceler = Canceler::new();
        let response = udp_process_query(
            &resolver,
            Message::new()
                .set_id(123)
                .set_recursion_desired(true)
                .set_recursion_available(true)
                .set_message_type(MessageType::Query)
                .add_query(Query::query(Name::from_str("www.baidu.com").unwrap(), RecordType::A)),
            &canceler,
        )
        .await
        .unwrap();

        assert_eq!(2, response.answer_count());

        assert_eq!(
            &RData::A(rdata::A(Ipv4Addr::new(1, 1, 1, 1))),
            response.answers()[0].data().unwrap()
        );
    }

    async fn udp_process_query(resolver: &DnsResolver, request: &Message, canceler: &Canceler) -> io::Result<Message> {
        let request_buf = request.to_vec()?;

        let output_buf = process_dns_udp_request(resolver, &request_buf, canceler).await?;

        match Message::from_vec(&output_buf[..]) {
            Ok(response) => Ok(response),
            Err(err) => Err(io::Error::new(io::ErrorKind::Other, err)),
        }
    }
}
