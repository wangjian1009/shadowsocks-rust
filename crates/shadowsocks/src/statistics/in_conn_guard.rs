use super::BuContext;

pub struct InConnGuard {
    context: BuContext,
}

impl InConnGuard {
    pub fn new(context: BuContext) -> Self {
        increment_counter!("total_tcp_conn_in",  "proto" => context.protocol.name(), "trans" => context.transport.as_ref().map(|t| t.name()).unwrap_or("none"));
        increment_gauge!("tcp_conn_in", 1.0, "proto" => context.protocol.name(), "trans" => context.transport.as_ref().map(|t| t.name()).unwrap_or("none"));
        Self { context }
    }
}

impl Drop for InConnGuard {
    fn drop(&mut self) {
        decrement_gauge!("tcp_conn_in", 1.0, "proto" => self.context.protocol.name(), "trans" => self.context.transport.as_ref().map(|t| t.name()).unwrap_or("none"));
    }
}
