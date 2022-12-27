use super::BuContext;

pub struct ConnGuard {
    context: BuContext,
    count: &'static str,
}

impl ConnGuard {
    pub fn new(context: BuContext, count: &'static str, total: Option<&'static str>) -> Self {
        total.map(|total| {
            increment_counter!(total,  "proto" => context.protocol.name(), "trans" => context.transport.as_ref().map(|t| t.name()).unwrap_or("none"));
        });
        increment_gauge!(count, 1.0, "proto" => context.protocol.name(), "trans" => context.transport.as_ref().map(|t| t.name()).unwrap_or("none"));
        Self { context, count }
    }
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        decrement_gauge!(self.count, 1.0, "proto" => self.context.protocol.name(), "trans" => self.context.transport.as_ref().map(|t| t.name()).unwrap_or("none"));
    }
}
