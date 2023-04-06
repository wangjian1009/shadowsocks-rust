use super::super::queue::Receiver;
use super::queue::ParallelJob;
use super::receive::ReceiveJob;
use super::send::SendJob;

use super::super::{tun, udp, Endpoint};
use super::types::Callbacks;

pub enum JobUnion<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>> {
    Outbound(SendJob<E, C, T, B>),
    Inbound(ReceiveJob<E, C, T, B>),
}

pub async fn worker<E: Endpoint, C: Callbacks, T: tun::Writer, B: udp::Writer<E>>(
    receiver: Receiver<JobUnion<E, C, T, B>>,
) {
    loop {
        tracing::trace!("pool worker awaiting job");
        match receiver.recv().await {
            None => {
                tracing::debug!("worker stopped");
                break;
            }
            Some(JobUnion::Inbound(job)) => {
                job.parallel_work();
                job.queue().consume().await;
            }
            Some(JobUnion::Outbound(job)) => {
                job.parallel_work();
                job.queue().consume().await;
            }
        }
    }
}
