use clap::{Arg, ArgAction, ArgMatches, Command, ValueHint};
use std::{future::Future, io, pin::Pin, process::ExitCode, sync::Arc, task};

use tokio::{fs::File, runtime::Builder, time::Duration};
use tracing::{error, trace};

use shadowsocks_service::{
    local::{context::ServiceContext, http::ProxyHttpStream, loadbalancing::ServerIdent, net::AutoProxyClientStream},
    shadowsocks::{canceler::Canceler, config::ServerType, context::Context, relay::socks5::Address, ServerConfig},
};

use hyper::{
    client::Client,
    http::{
        self,
        uri::{PathAndQuery, Scheme, Uri},
    },
    Body,
};
use tower::Service;

use crate::{config::LogConfig, logging};

pub fn define_command_line_options(mut app: Command) -> Command {
    #[cfg(feature = "logging")]
    {
        app = app
            .arg(
                Arg::new("VERBOSE")
                    .short('v')
                    .action(ArgAction::Count)
                    .help("Set log level"),
            )
            .arg(
                Arg::new("LOG_WITHOUT_TIME")
                    .long("log-without-time")
                    .action(ArgAction::SetTrue)
                    .help("Log without datetime prefix"),
            );
    }

    app = app
        .arg(
            Arg::new("TIMEOUT")
                .long("timeout")
                .num_args(1)
                .action(ArgAction::Set)
                .value_parser(clap::value_parser!(u64))
                .help("Server's timeout seconds for TCP relay"),
        )
        .arg(
            Arg::new("URL")
                .long("server-url")
                .num_args(1)
                .action(ArgAction::Set)
                .value_hint(ValueHint::Url)
                .help("Server address in SIP002 (https://shadowsocks.org/guide/sip002.html) URL"),
        )
        .arg(
            Arg::new("USER_AGENT")
                .help("Send User-Agent <name> to server")
                .long("user-agent")
                .short('A')
                .action(ArgAction::Set)
                .num_args(1),
        )
        .arg(
            Arg::new("REQUEST")
                .help("Specify request method to use")
                .long("request")
                .short('X')
                .action(ArgAction::Set)
                .num_args(1),
        )
        .arg(
            Arg::new("HEADER")
                .help("Pass custom header(s) to server")
                .long("header")
                .short('H')
                .action(ArgAction::Append),
        )
        .arg(Arg::new("TARGET_URL").help("url").action(ArgAction::Set).num_args(1))
        .arg(
            Arg::new("OUTPUT")
                .long("output")
                .short('o')
                .num_args(1)
                .action(ArgAction::Set)
                .help("result output file"),
        );

    app
}

pub fn main(matches: &ArgMatches, init_log: bool) -> ExitCode {
    #[cfg(feature = "logging")]
    let _log_guard = if init_log {
        let mut log_config = LogConfig::default();
        log_config.level = matches.get_count("VERBOSE") as u32;
        log_config.format.without_time = matches.get_flag("LOG_WITHOUT_TIME");
        Some(logging::init_with_config("sslocal", &log_config))
    } else {
        None
    };

    trace!("shadowsocks url {} build {}", crate::VERSION, crate::BUILD_TIME);

    let output_path = matches.get_one::<String>("OUTPUT");

    // 读取连接参数
    #[allow(unused_mut)]
    let mut server_url = matches.get_one::<String>("URL").expect("server url").clone();

    #[cfg(feature = "env-crypt")]
    if server_url.find("://").is_none() {
        server_url = match shadowsocks_service::decrypt(&server_url) {
            Ok(v) => v,
            Err(_err) => {
                trace!(error = ?_err, server_url = server_url, "decode error");
                server_url
            }
        };
    }

    let svr_cfg = match ServerConfig::from_url(&server_url) {
        Ok(t) => t,
        Err(err) => {
            error!(error = ?err, "server url parse error");
            return ExitCode::FAILURE;
        }
    };

    // let connect_timeout = matches.get_one::<u64>("TIMEOUT").copied().map(Duration::from_secs);

    // 构造目标URL
    let target_url = matches.get_one::<String>("TARGET_URL").expect("target url").clone();
    let target_url = match target_url.parse::<Uri>() {
        Ok(u) => {
            let mut parts = u.into_parts();
            if parts.scheme.is_none() {
                parts.scheme = Some(Scheme::HTTP);
            }

            if parts.path_and_query.is_none() {
                parts.path_and_query = Some(PathAndQuery::from_static("/"));
            }

            Uri::from_parts(parts).expect("target url rebuid")
        }
        Err(err) => {
            error!(error = ?err, url = target_url, "target url parse error");
            return ExitCode::FAILURE;
        }
    };

    trace!(target_url = ?target_url);

    // 构造http请求
    let mut req_builder = http::Request::builder().uri(target_url);

    // - method
    if let Some(request) = matches.get_one::<String>("REQUEST") {
        let method: http::Method = match request.parse() {
            Ok(m) => m,
            Err(err) => {
                error!(error = ?err, method = request, "unknown request");
                return ExitCode::FAILURE;
            }
        };

        req_builder = req_builder.method(method);
    }

    // - user-agent
    if let Some(user_agent) = matches.get_one::<String>("USER_AGENT") {
        req_builder = req_builder.header(hyper::header::USER_AGENT, user_agent);
    }

    // - headers
    if let Some(headers) = matches.get_many::<String>("HEADER") {
        for header in headers {
            let sep_pos = match header.find('=') {
                Some(p) => p,
                None => {
                    error!(header = header, "header format error");
                    return ExitCode::FAILURE;
                }
            };

            let key = &header[0..sep_pos];
            let value = header[sep_pos + 1..].trim();
            req_builder = req_builder.header(key, value);
        }
    }

    let request = req_builder.body(Body::empty()).expect("generate body error");
    trace!(request = ?request);

    // 构造tokio环境并执行任务
    let mut builder = Builder::new_current_thread();
    let runtime = builder.enable_all().build().expect("create tokio Runtime");

    runtime.block_on(async move {
        let canceler = Canceler::new();

        let context = Context::new_shared(ServerType::Local);
        let service_context = Arc::new(ServiceContext::new(context, canceler.waiter()));
        let server = Arc::new(
            ServerIdent::new(service_context.clone(), svr_cfg, Duration::MAX, Duration::MAX)
                .expect("create server ident"),
        );

        let connector = Connector {
            service_context,
            server,
        };

        let client = Client::builder().build(connector);

        let response = client.request(request).await;

        let r = if let Some(path) = output_path {
            let mut fs = match File::create(path).await {
                Ok(fs) => fs,
                Err(err) => {
                    error!(error = ?err, path = path, "open output file error");
                    return ExitCode::FAILURE;
                }
            };

            write_result(&mut fs, response).await
        } else {
            write_result(&mut tokio::io::stdout(), response).await
        };

        if let Err(err) = r {
            error!(error = ?err, "write response error");
            ExitCode::FAILURE
        } else {
            ExitCode::SUCCESS
        }
    })
}

async fn write_result<S>(w: &mut S, response: hyper::Result<http::Response<Body>>) -> io::Result<()>
where
    S: tokio::io::AsyncWriteExt + Unpin,
{
    match response {
        Ok(response) => write_response(w, response).await,
        Err(e) => {
            w.write(format!("{}", e).as_bytes()).await?;
            Ok(())
        }
    }
}

async fn write_response<S>(w: &mut S, response: http::Response<Body>) -> io::Result<()>
where
    S: tokio::io::AsyncWriteExt + Unpin,
{
    w.write_all(format!("{:?} {}\n", response.version(), response.status()).as_bytes())
        .await?;

    for header in response.headers().iter() {
        if let Ok(value) = header.1.to_str() {
            w.write_all(format!("{}: {}\n", header.0, value).as_bytes()).await?;
        } else {
            w.write_all(format!("{}: invalid\n", header.0).as_bytes()).await?;
        }
    }

    w.write_all(b"\n").await?;

    let body_data = hyper::body::to_bytes(response.into_body())
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    w.write_all(&body_data).await?;

    Ok(())
}

#[derive(Clone)]
struct Connector {
    service_context: Arc<ServiceContext>,
    server: Arc<ServerIdent>,
}

impl Service<Uri> for Connector {
    type Response = ProxyHttpStream;
    type Error = std::io::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _: &mut task::Context<'_>) -> task::Poll<Result<(), Self::Error>> {
        task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let service_context = self.service_context.clone();
        let server = self.server.clone();

        Box::pin(async move {
            // 从URL获取目标地址
            let port = match uri.port() {
                Some(port) => port.as_u16(),
                None => match uri.scheme().map(|s| s.as_str()) {
                    None => 80,
                    Some("http") => 80,
                    Some("https") => 443,
                    Some(..) => {
                        error!(uri = ?uri, "target url no port");
                        return Err(io::Error::new(io::ErrorKind::Other, "target url no host"));
                    }
                },
            };

            let target_addr = match uri.host() {
                Some(host) => Address::parse_str_host(host, port),
                None => {
                    return Err(io::Error::new(io::ErrorKind::Other, "target url no host"));
                }
            };
            trace!(target_addr = ?target_addr);

            let stream = AutoProxyClientStream::connect_proxied(&service_context, &server, &target_addr).await?;

            Ok(ProxyHttpStream::connect_http(stream))
        })
    }
}
