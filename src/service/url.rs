use clap::{Arg, ArgAction, ArgMatches, Command, ValueHint};
use std::{future, io, process::ExitCode, sync::Arc};

use tokio::{fs::File, io::AsyncWriteExt, runtime::Builder, time::Duration};
use tracing::{error, trace};

use shadowsocks_service::{
    local::{api, context::ServiceContext, loadbalancing::ServerIdent},
    shadowsocks::{canceler::Canceler, config::ServerType, context::Context, ServerConfig},
};

use hyper::{
    http::{
        self,
        uri::{PathAndQuery, Scheme, Uri},
    },
    Body,
};

use crate::{config::LogConfig, logging};

#[derive(Debug)]
enum UrlTestError {
    ArgumentError(String),
    Api(api::ApiError),
    ContentLengthMismatch(usize, usize),
    ResponseBodyTransferError(hyper::Error),
    Timeout(String),
}

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
            Arg::new("DATA")
                .long("data")
                .short('d')
                .num_args(1)
                .action(ArgAction::Set)
                .help("request body file"),
        )
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

    // 构造tokio环境并执行任务
    let mut builder = Builder::new_current_thread();
    let runtime = builder.enable_all().build().expect("create tokio Runtime");

    runtime.block_on(async move {
        let output_path = matches.get_one::<String>("OUTPUT");
        let timeout = matches.get_one::<u64>("TIMEOUT").copied().map(Duration::from_millis);

        let request = match build_request(matches).await {
            Ok(request) => request,
            Err(err) => {
                return write_output(output_path, Err(err)).await;
            }
        };
        trace!(request = ?request);

        let svr_cfg = match build_svr_cfg(matches) {
            Ok(svr_cfg) => svr_cfg,
            Err(err) => {
                return write_output(output_path, Err(err)).await;
            }
        };

        let canceler = Canceler::new();

        let context = Context::new_shared(ServerType::Local);
        let service_context = Arc::new(ServiceContext::new(context, canceler.waiter()));
        let server = match ServerIdent::new(service_context.clone(), svr_cfg, Duration::MAX, Duration::MAX) {
            Ok(server) => Arc::new(server),
            Err(err) => {
                return write_output(output_path, Err(UrlTestError::ArgumentError(format!("{:?}", err)))).await;
            }
        };

        tokio::select! {
            _r = wait_timeout(timeout) => {
                write_output(output_path, Err(UrlTestError::Timeout("GlobalTimeout".to_string()))).await
            }
            r = api::request(request, service_context, server) => {
                let response = r.map_err(|e| UrlTestError::Api(e));
                trace!(response = ?response);

                write_output(output_path, response).await
            }
        }
    })
}

async fn wait_timeout(timeout: Option<Duration>) {
    if let Some(timeout) = timeout {
        tokio::time::sleep(timeout).await
    } else {
        future::pending().await
    }
}

fn build_svr_cfg(matches: &ArgMatches) -> Result<ServerConfig, UrlTestError> {
    // 读取连接参数
    #[allow(unused_mut)]
    let mut server_url = match matches.get_one::<String>("URL") {
        Some(v) => v.clone(),
        None => return Err(UrlTestError::ArgumentError("URL not configure".to_string())),
    };

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
            error!(error = ?err, url = server_url, "server url parse error");
            return Err(UrlTestError::ArgumentError(format!(
                "server url parse error, url = {}, error = {}",
                server_url, err,
            )));
        }
    };

    Ok(svr_cfg)
}

async fn build_request(matches: &ArgMatches) -> Result<http::Request<Body>, UrlTestError> {
    // 构造目标URL
    let target_url = match matches.get_one::<String>("TARGET_URL") {
        Some(v) => v.clone(),
        None => return Err(UrlTestError::ArgumentError("TARGET_URL not configure".to_string())),
    };
    let target_url = match target_url.parse::<Uri>() {
        Ok(u) => {
            let mut parts = u.into_parts();
            if parts.scheme.is_none() {
                parts.scheme = Some(Scheme::HTTP);
            }

            if parts.path_and_query.is_none() {
                parts.path_and_query = Some(PathAndQuery::from_static("/"));
            }

            match Uri::from_parts(parts) {
                Ok(uri) => uri,
                Err(err) => {
                    return Err(UrlTestError::ArgumentError(format!(
                        "rebuild TARGET_URL error, error = {:?}",
                        err
                    )))
                }
            }
        }
        Err(err) => {
            error!(error = ?err, url = target_url, "target url parse error");
            return Err(UrlTestError::ArgumentError(format!(
                "TARGET_URL format error, url={}, error={:?}",
                target_url, err
            )));
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
                return Err(UrlTestError::ArgumentError(format!(
                    "method {} not support, error={:?}",
                    request, err
                )));
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
                    return Err(UrlTestError::ArgumentError(format!(
                        "header format error, header = {}",
                        header
                    )));
                }
            };

            let key = &header[0..sep_pos];
            let value = header[sep_pos + 1..].trim();
            req_builder = req_builder.header(key, value);
        }
    }

    // body
    let request = if let Some(data_file) = matches.get_one::<String>("DATA") {
        let body = match tokio::fs::read(data_file).await {
            Ok(body) => body,
            Err(err) => {
                return Err(UrlTestError::ArgumentError(format!(
                    "read body from {} error, error = {:?}",
                    data_file, err
                )));
            }
        };
        req_builder.body(Body::from(body))
    } else {
        req_builder.body(Body::empty())
    }
    .expect("generate body error");

    Ok(request)
}

async fn write_output(output_path: Option<&String>, result: Result<http::Response<Body>, UrlTestError>) -> ExitCode {
    if let Some(output_path) = output_path {
        let mut writing_result = Some(result);
        let mut write_count = 0;
        while writing_result.is_some() {
            write_count = write_count + 1;

            let mut fs = match File::create(output_path).await {
                Ok(fs) => fs,
                Err(err) => {
                    error!(error = ?err, path = output_path, "open output file error");
                    return ExitCode::FAILURE;
                }
            };

            let result = writing_result.unwrap();

            match write_result(&mut fs, result).await {
                Ok(()) => match fs.sync_all().await {
                    Ok(()) => {
                        trace!(output = output_path, "response write success");
                        break;
                    }
                    Err(err) => {
                        error!(error = ?err, output = output_path, "response write flush error");
                        return ExitCode::FAILURE;
                    }
                },
                Err(err) => match err {
                    WriteResultError::TransferError(e) => {
                        assert!(write_count == 1);
                        writing_result = Some(Err(UrlTestError::ResponseBodyTransferError(e)))
                    }
                    WriteResultError::ContentLengthMismatch(expect, readed) => {
                        assert!(write_count == 1);
                        writing_result = Some(Err(UrlTestError::ContentLengthMismatch(expect, readed)))
                    }
                    WriteResultError::LocalIoError(e) => {
                        error!(error = ?e, output = output_path, "response write local io error");
                        return ExitCode::FAILURE;
                    }
                },
            }
        }
    } else {
        match write_result(&mut tokio::io::stdout(), result).await {
            Ok(()) => {}
            Err(err) => {
                error!(error = ?err, "response write error");
            }
        }
    }

    ExitCode::SUCCESS
}

#[derive(Debug)]
enum WriteResultError {
    TransferError(hyper::Error),
    ContentLengthMismatch(usize, usize),
    LocalIoError(io::Error),
}

async fn write_result<S>(
    w: &mut S,
    response: Result<http::Response<Body>, UrlTestError>,
) -> Result<(), WriteResultError>
where
    S: AsyncWriteExt + Unpin,
{
    match response {
        Ok(response) => {
            let content_length = if let Some(content_length) = response.headers().get(http::header::CONTENT_LENGTH) {
                if let Ok(content_length) = content_length.to_str() {
                    match content_length.parse::<usize>() {
                        Ok(v) => Some(v),
                        Err(..) => None,
                    }
                } else {
                    None
                }
            } else {
                None
            };

            let body_size = write_response(w, response).await?;

            if let Some(content_length) = content_length {
                if content_length != body_size {
                    return Err(WriteResultError::ContentLengthMismatch(content_length, body_size));
                }
            }

            Ok(())
        }
        Err(UrlTestError::ArgumentError(msg)) => write_lines(w, &["ArgumentError", msg.as_str()]).await,
        Err(UrlTestError::ContentLengthMismatch(expect, received)) => {
            write_lines(
                w,
                &[
                    "ContentLengthMismatch",
                    &format!("expect={}, received={}", expect, received),
                ],
            )
            .await
        }
        Err(UrlTestError::ResponseBodyTransferError(err)) => {
            write_lines(w, &["ResponseBodyTransferError", &format!("{:?}", err)]).await
        }
        Err(UrlTestError::Api(e)) => match e {
            api::ApiError::Other(msg) => write_error_lines(w, "Other", msg.as_ref()).await,
        },
        Err(UrlTestError::Timeout(msg)) => write_lines(w, &["Timeout", msg.as_str()]).await,
    }
}

async fn write_error_lines<S>(w: &mut S, err: &str, msg: Option<&String>) -> Result<(), WriteResultError>
where
    S: AsyncWriteExt + Unpin,
{
    if let Some(msg) = msg {
        write_lines(w, &[err, msg]).await
    } else {
        write_lines(w, &[err]).await
    }
}

async fn write_lines<S>(w: &mut S, lines: &[&str]) -> Result<(), WriteResultError>
where
    S: AsyncWriteExt + Unpin,
{
    for l in lines {
        write_line(w, l).await?;
    }
    Ok(())
}

async fn write_line<S>(w: &mut S, line: &str) -> Result<(), WriteResultError>
where
    S: AsyncWriteExt + Unpin,
{
    w.write(line.as_bytes())
        .await
        .map_err(|e| WriteResultError::LocalIoError(e))?;
    w.write(b"\n").await.map_err(|e| WriteResultError::LocalIoError(e))?;
    Ok(())
}

async fn write_response<S>(w: &mut S, response: http::Response<Body>) -> Result<usize, WriteResultError>
where
    S: AsyncWriteExt + Unpin,
{
    write_line(w, &format!("{:?} {}", response.version(), response.status())).await?;

    for header in response.headers().iter() {
        if let Ok(value) = header.1.to_str() {
            write_line(w, &format!("{}: {}", header.0, value)).await?;
        } else {
            write_line(w, &format!("{}: invalid", header.0)).await?;
        }
    }

    write_line(w, "").await?;

    let body_data = hyper::body::to_bytes(response.into_body())
        .await
        .map_err(|e| WriteResultError::TransferError(e))?;

    w.write_all(&body_data)
        .await
        .map_err(|e| WriteResultError::LocalIoError(e))?;

    Ok(body_data.len())
}
