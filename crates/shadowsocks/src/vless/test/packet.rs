use super::*;

use futures::{future, FutureExt};
use rand::RngCore;

use crate::transport::{PacketMutWrite, PacketRead};

const BLOCK_SIZE: usize = 1024;
const TOTAL_SIZE: usize = 1024 * 128;

#[tokio::test]
async fn packet_basic() {
    let _ = env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .is_test(true)
        .try_init();

    let mut cfg = Config::new();
    cfg.add_user(0, "66ad4540-b58c-4ad2-9926-ea63445a9b57", None).unwrap();

    let modifiler = DataModifiler::Xor('c' as u8);
    let modifiler = Arc::new(modifiler);

    // 创建服务
    let (_h, port) = start_server(&cfg, modifiler.clone()).await.unwrap();

    // 测试数据
    let run_count = 1;
    let mut vfut = Vec::with_capacity(run_count);
    for i in 0..run_count {
        let target_addr = Address::DomainNameAddress("www.baidu.com".to_string(), (i + 1) as u16);
        vfut.push(test_one_connection(&cfg, port, target_addr, modifiler.clone()).boxed());
    }

    while !vfut.is_empty() {
        let (res, _idx, left_vfut) = future::select_all(vfut).await;
        res.unwrap();
        vfut = left_vfut
    }
}

async fn test_one_connection(
    cfg: &Config,
    port: u16,
    target_addr: Address,
    modifiler: Arc<DataModifiler>,
) -> io::Result<()> {
    let (mut r, mut w) = connect_packet(cfg, port, target_addr.clone()).await?;

    let mut client_send = vec![0u8; TOTAL_SIZE]; // 1048576
    rand::thread_rng().fill_bytes(&mut client_send);

    let mut client_expected = client_send.clone();
    assert_eq!(client_expected, client_send);

    modifiler.update(&mut client_expected);

    let target_addr: ServerAddr = target_addr.into();
    {
        let target_addr = target_addr.clone();
        tokio::spawn(async move {
            let mut to_send = &mut client_send[..];
            while to_send.len() > 0 {
                let send_sz = std::cmp::min(BLOCK_SIZE, to_send.len());

                w.write_to_mut(&to_send[..send_sz], &target_addr)
                    .await
                    .unwrap_or_else(|err| panic!("客户端发送数据失败 {}", err));

                to_send = &mut to_send[send_sz..];
            }
            log::error!("客户端发送数据成功");
        });
    }

    let mut client_received = vec![0u8; TOTAL_SIZE];

    let mut received_len = 0;
    let mut recv = &mut client_received[..];
    let mut recv_expect = &mut client_expected[..];
    while recv.len() > 0 {
        let (sz, addr) = r.read_from(recv).await.unwrap_or_else(|err| {
            panic!(
                "客户端接受数据失败 {}, received={}, left={}",
                err,
                received_len,
                recv.len()
            )
        });
        received_len += sz;

        assert_eq!(&recv[..sz], &recv_expect[..sz]);
        assert_eq!(addr, target_addr);

        recv = &mut recv[sz..];
        recv_expect = &mut recv_expect[sz..];
    }

    log::info!("test client transform success");

    assert_eq!(client_received, client_expected);

    Ok(())
}
