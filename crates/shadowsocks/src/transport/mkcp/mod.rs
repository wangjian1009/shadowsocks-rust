mod acceptor;
mod config;
mod connection;
mod connector;
mod io;
mod receiving;
mod segment;
mod sending;
mod statistic;

pub use acceptor::MkcpAcceptor;
pub use config::MkcpConfig;
pub use connector::MkcpConnector;
pub use statistic::StatisticStat;

use connection::{MkcpConnMetadata, MkcpConnWay, MkcpConnection};
use receiving::ReceivingWorker;
use sending::SendingWorker;

fn new_error<T: ToString>(message: T) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, format!("mkcp: {}", message.to_string()))
}

// #[cfg(test)]
// mod test;
