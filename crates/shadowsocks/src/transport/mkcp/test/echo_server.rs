use super::*;
use crate::transport::Acceptor;
use std::{io::Cursor, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn test() {
    let _ = env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .is_test(true)
        .try_init();

    let config = Arc::new(MkcpConfig::default());

    // 创建服务
    let listener = direct::create_acceptor(config.clone(), 0, None).await;
    let listen_addr = listener.local_addr().unwrap();

    // 启动回显服务
    let acceptor_task = direct::start_echo_server(Arc::new(listener));
    defer!({
        acceptor_task.abort();
    });

    // 客户端连接
    {
        let stream = direct::connect_to(config, listen_addr.port(), None).await.unwrap();

        let (mut r, mut w) = tokio::io::split(stream);
        const SENDING_DATA: &'static [u8] = b"hello world";

        // 启动发送数据服务
        tokio::spawn(async move {
            w.write_all_buf(&mut Cursor::new(SENDING_DATA))
                .await
                .unwrap_or_else(|err| panic!("客户端发送数据失败 {}", err));
        });

        let mut recv_buf = [0u8; SENDING_DATA.len()];

        r.read_exact(&mut recv_buf)
            .await
            .unwrap_or_else(|err| panic!("客户端接受数据失败 {}", err));

        assert_eq!(&recv_buf, SENDING_DATA);
    }

    tokio::time::sleep(Duration::from_secs(5)).await;
}
