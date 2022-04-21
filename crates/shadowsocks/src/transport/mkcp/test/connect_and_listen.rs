// use super::*;
// use futures::{future, FutureExt};
// use rand::RngCore;
// use std::{io, io::Cursor, sync::atomic::*, time::Duration};
// use tokio::io::{AsyncReadExt, AsyncWriteExt};

// use crate::{
//     test::transfer,
//     transport::{Acceptor, Connection},
// };

// #[tokio::test(flavor = "multi_thread")]
// async fn test() {
//     let _ = env_logger::builder()
//         .filter_level(log::LevelFilter::Info)
//         .is_test(true)
//         .try_init();

//     let config = MkcpConfig::default();
//     let config = Arc::new(config);

//     // 创建服务
//     let server_statistic = Arc::new(StatisticStat::new());
//     let mut listener = direct::create_acceptor(config.clone(), 0, Some(server_statistic.clone())).await;
//     let listen_port = listener.local_addr().unwrap().port();

//     // 启动数据会送服务
//     let acceptor_task = {
//         tokio::spawn(async move {
//             while let Ok((connection, _peer_addr)) = listener.accept().await {
//                 let stream = match connection {
//                     Connection::Stream(stream) => stream,
//                     Connection::Packet { .. } => unreachable!(),
//                 };
//                 let (mut r, mut w) = tokio::io::split(stream);

//                 tokio::spawn(async move {
//                     let total = AtomicU32::new(0);
//                     match transfer(&mut r, &mut w, move |buf| {
//                         for i in 0..buf.len() {
//                             buf[i] = buf[i] ^ 'c' as u8;
//                         }

//                         total.fetch_add(buf.len() as u32, Ordering::SeqCst);
//                         Ok(())
//                     })
//                     .await
//                     {
//                         Ok(len) => log::info!("test server transform success, len={}", len),
//                         Err(err) => log::error!("test transform complete error {}", err),
//                     };
//                 });
//             }
//         })
//     };
//     defer!({
//         acceptor_task.abort();
//     });

//     let run_count = 1;
//     let mut vfut = Vec::with_capacity(run_count);
//     let client_statistic = Arc::new(StatisticStat::new());
//     for _i in 0..run_count {
//         let listen_port = listen_port;
//         let config = config.clone();
//         vfut.push(test_one_connection(config, listen_port, Some(client_statistic.clone())).boxed());
//     }

//     while !vfut.is_empty() {
//         let (res, _idx, left_vfut) = future::select_all(vfut).await;
//         res.unwrap();
//         vfut = left_vfut
//     }

//     for _i in 0..60 {
//         if listener.active_connections() <= 0 {
//             break;
//         }
//         tokio::time::sleep(Duration::from_millis(500)).await
//     }

//     assert_eq!(0, listener.active_connections());

//     log::error!("xxxxx: server-stastics={}", server_statistic);
//     log::error!("xxxxx: client-stastics={}", client_statistic);
//     tokio::time::sleep(Duration::from_secs(10)).await;
// }

// async fn test_one_connection(
//     config: Arc<MkcpConfig>,
//     port: u16,
//     statistic: Option<Arc<StatisticStat>>,
// ) -> io::Result<()> {
//     let stream = direct::connect_to(config, port, statistic).await?;

//     let (mut r, mut w) = tokio::io::split(stream);

//     let mut client_send = vec![0u8; 1024 * 1024]; // 1048576
//     rand::thread_rng().fill_bytes(&mut client_send);

//     let mut client_expected = vec![0u8; 1024 * 1024];
//     for i in 0..client_send.len() {
//         client_expected[i] = client_send[i] ^ 'c' as u8;
//     }

//     tokio::spawn(async move {
//         w.write_all_buf(&mut Cursor::new(client_send))
//             .await
//             .unwrap_or_else(|err| panic!("客户端发送数据失败 {}", err));
//         log::error!("客户端发送数据成功");
//     });

//     let mut client_received = vec![0u8; 1024 * 1024];

//     r.read_exact(&mut client_received)
//         .await
//         .unwrap_or_else(|err| panic!("客户端接受数据失败 {}", err));

//     log::info!("test client transform success");

//     assert_eq!(client_received, client_expected);

//     Ok(())
// }
