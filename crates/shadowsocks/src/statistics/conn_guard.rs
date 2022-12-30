use super::BuContext;
use crate::{
    net::{AddrCategory, AddrType},
    ServerAddr,
};

pub enum Target {
    Net(AddrCategory, AddrType),
    Inapp(&'static str),
}

impl From<&ServerAddr> for Target {
    fn from(value: &ServerAddr) -> Self {
        Self::Net(AddrCategory::from(value), AddrType::from(value))
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
        let proto = context.protocol().name();
        let trans = context.transport().as_ref().map(|t| t.name()).unwrap_or("none");

        match &target {
            Target::Net(category, t) => {
                if let Some(total) = total {
                    increment_counter!(total,  "proto" => proto, "trans" => trans, "category" => category.name(), "type" => t.name());
                };
                increment_gauge!(count, 1.0, "proto" => proto, "trans" => trans, "category" => category.name(), "type" => t.name());
            }
            Target::Inapp(p) => {
                if let Some(total) = total {
                    increment_counter!(total,  "proto" => proto, "trans" => trans, "category" => *p);
                };
                increment_gauge!(count, 1.0, "proto" => proto, "trans" => trans, "category" => *p);
            }
        }

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
        if let Some(target) = self.target.as_ref() {
            match target {
                Target::Net(category, t) => {
                    decrement_gauge!(self.count, 1.0, "proto" => self.context.protocol().name(), "trans" => self.context.transport().as_ref().map(|t| t.name()).unwrap_or("none"), "category" => category.name(), "type" => t.name());
                }
                Target::Inapp(p) => {
                    decrement_gauge!(self.count, 1.0, "proto" => self.context.protocol().name(), "trans" => self.context.transport().as_ref().map(|t| t.name()).unwrap_or("none"), "category" => *p);
                }
            }
        } else {
            decrement_gauge!(self.count, 1.0, "proto" => self.context.protocol().name(), "trans" => self.context.transport().as_ref().map(|t| t.name()).unwrap_or("none"));
        }
    }
}
