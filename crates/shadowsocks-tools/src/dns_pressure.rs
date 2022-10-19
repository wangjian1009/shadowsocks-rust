use std::time::Duration;

use byteorder::{BigEndian, ByteOrder};
use clap::{Arg, ArgAction, Command};
use shadowsocks::{
    config::{ServerAddr, ServerType},
    context::Context,
    net::{ConnectOpts, TcpStream, UdpSocket},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time,
};
use trust_dns_proto::{
    op::{Message, Query},
    rr::{Name, RecordType},
};

#[tokio::main]
async fn main() {
    env_logger::init();

    let matches = Command::new("dns-pressure")
        .arg(
            Arg::new("OUTBOUND_BIND_INTERFACE")
                .long("outbound-bind-interface")
                .action(ArgAction::Set),
        )
        .arg(
            Arg::new("NAMESERVER_ADDR")
                .long("nameserver-addr")
                .action(ArgAction::Set)
                .required(true),
        )
        .arg(
            Arg::new("DNS_QUERY_NAME")
                .long("dns-query-name")
                .action(ArgAction::Set)
                .required(true),
        )
        .arg(
            Arg::new("TOTAL_CLIENT_COUNT")
                .long("total-client-count")
                .action(ArgAction::Set),
        )
        .arg(Arg::new("UDP").long("udp").conflicts_with("TCP"))
        .arg(Arg::new("TCP").long("tcp").conflicts_with("UDP"))
        .arg(Arg::new("TIMEOUT").long("timeout").action(ArgAction::Set))
        .get_matches();

    let mut connect_opts = ConnectOpts::default();
    if let Some(outbound_bind_interface) = matches.get_one::<String>("OUTBOUND_BIND_INTERFACE") {
        connect_opts.bind_interface = Some(outbound_bind_interface.to_owned());
    }

    let dns_query_name = matches.get_one::<String>("DNS_QUERY_NAME").unwrap();
    let nameserver_addr = matches.get_one::<String>("NAMESERVER_ADDR").cloned().unwrap();

    let total_client_count = matches.get_one::<usize>("TOTAL_CLIENT_COUNT").cloned().unwrap_or(10);

    let use_udp = matches.get_flag("UDP") || !matches.get_flag("TCP");

    let timeout = Duration::from_secs(matches.get_one::<u64>("TIMEOUT").cloned().unwrap_or(5));

    let name = Name::from_utf8(dns_query_name).expect("name");
    let query = Query::query(name, RecordType::A);

    let mut message = Message::new();
    message.set_recursion_desired(true);
    message.add_query(query);

    let context = Context::new_shared(ServerType::Local);

    let mut tasks = Vec::new();

    for _ in 0..total_client_count {
        let mut message = message.clone();
        let context = context.clone();
        let connect_opts = connect_opts.clone();

        let server_addr = nameserver_addr.parse::<ServerAddr>().unwrap();
        let handle = tokio::spawn(async move {
            loop {
                message.set_id(rand::random());

                let mut buffer = message.to_vec().expect("query serialize");

                let recv_message = if use_udp {
                    let socket = UdpSocket::connect_server_with_opts(&context, &server_addr, &connect_opts)
                        .await
                        .expect("connect");

                    let n = socket.send(&buffer).await.expect("send");
                    if n < buffer.len() {
                        eprintln!("message sent shorter, expected {} bytes, but {} bytes", buffer.len(), n);
                    }

                    let mut recv_buffer = [0u8; 65535];
                    let n = match time::timeout(timeout, socket.recv(&mut recv_buffer)).await {
                        Ok(Ok(n)) => n,
                        Ok(Err(err)) => {
                            eprintln!("socket recv error: {}", err);
                            continue;
                        }
                        Err(..) => {
                            eprintln!("recv timeout");
                            continue;
                        }
                    };

                    match Message::from_vec(&recv_buffer[..n]) {
                        Ok(m) => m,
                        Err(err) => {
                            eprintln!("received invalid DNS message, err: {}", err);
                            continue;
                        }
                    }
                } else {
                    let mut stream = TcpStream::connect_server_with_opts(&context, &server_addr, &connect_opts)
                        .await
                        .expect("connect");

                    // Prepend length
                    let req_len = buffer.len();
                    buffer.resize(req_len + 2, 0);
                    buffer.copy_within(..req_len, 2);
                    BigEndian::write_u16(&mut buffer[0..2], req_len as u16);

                    stream.write_all(&buffer).await.expect("write_all");

                    let mut rsp_length_buffer = [0u8; 2];
                    if let Err(..) = time::timeout(timeout, stream.read_exact(&mut rsp_length_buffer)).await {
                        eprintln!("read length timeout");
                        continue;
                    }

                    let rsp_length = BigEndian::read_u16(&rsp_length_buffer);
                    let mut recv_buffer = vec![0u8; rsp_length as usize];

                    match time::timeout(timeout, stream.read_exact(&mut recv_buffer)).await {
                        Ok(Ok(..)) => {}
                        Ok(Err(err)) => {
                            eprintln!("socket read error: {}", err);
                            continue;
                        }
                        Err(..) => {
                            eprintln!("read timeout");
                            continue;
                        }
                    };

                    match Message::from_vec(&recv_buffer) {
                        Ok(m) => m,
                        Err(err) => {
                            eprintln!("received invalid DNS message, err: {}", err);
                            continue;
                        }
                    }
                };

                if recv_message.id() != message.id() {
                    eprintln!(
                        "received unmatched DNS query respond, expected: {}, but: {}",
                        message.id(),
                        recv_message.id()
                    );
                }
            }
        });
        tasks.push(handle);
    }

    for task in tasks {
        let _ = task.await;
    }
}
