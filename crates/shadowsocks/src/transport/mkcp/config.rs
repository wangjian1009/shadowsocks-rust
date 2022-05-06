use super::super::{HeaderConfig, HeaderPolicy, Security, SecurityConfig};

#[derive(Clone, Debug, PartialEq)]
pub struct MkcpConfig {
    // 最大传输单元（maximum transmission unit），请选择一个介于 576 - 1460 之间的值。默认值为 1350
    pub mtu: u32,
    // 传输时间间隔（transmission time interval），单位毫秒（ms），mKCP 将以这个时间频率发送数据。请选译一个介于 10 - 100 之间的值。默认值为 50
    pub tti: u32,
    // 上行链路容量，即主机发出数据所用的最大带宽，单位 MB/s，默认值 5。 可以设置为 0，表示一个非常小的带宽；
    pub uplink_capacity: u32,
    // 下行链路容量，即主机接收数据所用的最大带宽，单位 MB/s，默认值 20。可以设置为 0，表示一个非常小的带宽；
    pub downlink_capacity: u32,
    // 是否启用拥塞控制，默认值为 false。
    // 开启拥塞控制之后，V2Ray 会自动监测网络质量，当丢包严重时，会自动降低吞吐量；当网络畅通时，也会适当增加吞吐量。
    pub congestion: bool,
    // 单个连接的写入缓冲区大小，单位是 MB。默认值为 2。
    pub write_buffer: u32,
    // 单个连接的读取缓冲区大小，单位是 MB。默认值为 2。
    pub read_buffer: u32,
    // mKCP 进行伪装, utp、srtp、wechat-video、dtls、wireguard 或者 none
    pub header_config: Option<HeaderConfig>,
    pub seed: Option<String>,
}

impl MkcpConfig {
    pub fn create_header(&self) -> Option<HeaderPolicy> {
        match self.header_config.as_ref() {
            None => None,
            Some(head_config) => Some(head_config.create_policy()),
        }
    }

    pub fn sending_in_flight_size(&self) -> u32 {
        let mut size = (self.uplink_capacity as usize) * 1024 * 1024 / self.mtu as usize / (1000 / self.tti as usize);
        if size < 8 {
            size = 8;
        }
        size as u32
    }

    pub fn sending_buffer_size(&self) -> u32 {
        self.write_buffer / self.mtu
    }

    pub fn receiving_in_flight_size(&self) -> u32 {
        let mut size = self.downlink_capacity * 1024 * 1024 / self.mtu / (1000 / self.tti);
        if size < 8 {
            size = 8;
        }
        size
    }

    pub fn receiving_buffer_size(&self) -> u32 {
        self.read_buffer / self.mtu
    }

    pub fn create_security(&self) -> Security {
        match self.seed.as_ref() {
            Some(seed) => SecurityConfig::AESGCM { seed: seed.clone() },
            None => SecurityConfig::Simple,
        }
        .create_security()
    }
}

impl Default for MkcpConfig {
    fn default() -> Self {
        Self {
            mtu: 1350,
            tti: 50,
            uplink_capacity: 5,
            downlink_capacity: 20,
            congestion: false,
            write_buffer: 2 * 1024 * 1024,
            read_buffer: 2 * 1024 * 1024,
            header_config: None,
            seed: None,
        }
    }
}
