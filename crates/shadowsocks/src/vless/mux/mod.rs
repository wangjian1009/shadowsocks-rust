mod client;
mod encoding;
mod frame;
mod server;
mod session;
mod shared_stream;
mod stream;

use shared_stream::SharedStream;

pub use client::{ClientStrategy, ClientWorker, WorkerPicker};
pub use frame::{Destination, TargetNetwork};
pub use stream::MuxStream;

pub use server::serve;
