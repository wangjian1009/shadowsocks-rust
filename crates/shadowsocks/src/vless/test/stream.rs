use super::*;

use futures::{future, FutureExt};
use rand::RngCore;
use std::{io::Cursor, str::FromStr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
#[traced_test]
async fn stream_basic() {
    let uuid = common::UUID::from_str("66ad4540-b58c-4ad2-9926-ea63445a9b57").unwrap();

    let mut cfg = Config::new();
    cfg.clients.push(protocol::User {
        level: 0,
        email: None,
        account: protocol::Account::new(uuid),
    });

    let modifiler = DataModifiler::Xor('c' as u8);
    let modifiler = Arc::new(modifiler);

    // 创建服务
    let (_h, port) = start_server(&cfg, modifiler).await.unwrap();

    // 测试数据
    let run_count = 10;
    let mut vfut = Vec::with_capacity(run_count);
    for i in 0..run_count {
        let target_addr = Address::DomainNameAddress("www.baidu.com".to_string(), i as u16);
        vfut.push(test_one_connection(&cfg, port, target_addr).boxed());
    }

    while !vfut.is_empty() {
        let (res, _idx, left_vfut) = future::select_all(vfut).await;
        res.unwrap();
        vfut = left_vfut
    }
}

async fn test_one_connection(cfg: &Config, port: u16, target_addr: Address) -> io::Result<()> {
    let stream = connect_stream(cfg, port, target_addr).await?;
    let (mut r, mut w) = tokio::io::split(stream);

    let mut client_send = vec![0u8; 1024 * 1024]; // 1048576
    rand::thread_rng().fill_bytes(&mut client_send);

    let mut client_expected = vec![0u8; 1024 * 1024];
    for i in 0..client_send.len() {
        client_expected[i] = client_send[i] ^ 'c' as u8;
    }

    tokio::spawn(async move {
        w.write_all_buf(&mut Cursor::new(client_send))
            .await
            .unwrap_or_else(|err| panic!("客户端发送数据失败 {}", err));
        tracing::error!("客户端发送数据成功");
    });

    let mut client_received = vec![0u8; 1024 * 1024];

    r.read_exact(&mut client_received)
        .await
        .unwrap_or_else(|err| panic!("客户端接受数据失败 {}", err));

    tracing::info!("test client transform success");

    assert_eq!(client_received, client_expected);

    Ok(())
}
