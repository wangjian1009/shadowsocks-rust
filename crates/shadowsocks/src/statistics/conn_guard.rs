use super::BuContext;
use crate::net::AddrCategory;

pub enum Target {
    Net(AddrCategory),
    Inapp(&'static str),
}

impl Target {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Net(category) => category.name(),
            Self::Inapp(name) => name,
        }
    }
}

pub struct ConnGuard {
    context: BuContext,
    target: Option<Target>,
    count: &'static str,
}

impl ConnGuard {
    pub fn new(context: BuContext, count: &'static str, total: Option<&'static str>) -> Self {
        total.map(|total| {
            increment_counter!(total,  "proto" => context.protocol().name(), "trans" => context.transport().as_ref().map(|t| t.name()).unwrap_or("none"));
        });
        increment_gauge!(count, 1.0, "proto" => context.protocol().name(), "trans" => context.transport().as_ref().map(|t| t.name()).unwrap_or("none"));
        Self {
            context,
            count,
            target: None,
        }
    }

    pub fn new_with_target(
        context: BuContext,
        target: Target,
        count: &'static str,
        total: Option<&'static str>,
    ) -> Self {
        total.map(|total| {
            increment_counter!(total,  "proto" => context.protocol().name(), "trans" => context.transport().as_ref().map(|t| t.name()).unwrap_or("none"), "category" => target.name());
        });
        increment_gauge!(count, 1.0, "proto" => context.protocol().name(), "trans" => context.transport().as_ref().map(|t| t.name()).unwrap_or("none"), "category" => target.name());
        Self {
            context,
            count,
            target: Some(target),
        }
    }

    pub fn bu_context(&self) -> &BuContext {
        &self.context
    }
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        if let Some(category) = self.target.as_ref() {
            decrement_gauge!(self.count, 1.0, "proto" => self.context.protocol().name(), "trans" => self.context.transport().as_ref().map(|t| t.name()).unwrap_or("none"), "category" => category.name());
        } else {
            decrement_gauge!(self.count, 1.0, "proto" => self.context.protocol().name(), "trans" => self.context.transport().as_ref().map(|t| t.name()).unwrap_or("none"));
        }
    }
}
