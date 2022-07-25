use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use hyper::{service::Service, Body, Request, Response};

use super::{context::MaintainServerContext, GenericError, GenericResult};

pub struct Svc {
    context: Arc<MaintainServerContext>,
}

impl Service<Request<Body>> for Svc {
    type Error = GenericError;
    type Future = Pin<Box<dyn Future<Output = GenericResult<Self::Response>> + Send>>;
    type Response = Response<Body>;

    fn poll_ready(&mut self, _: &mut Context) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<Body>) -> Self::Future {
        let context = self.context.clone();
        Box::pin(async move { context.handle_request(req).await })
    }
}

pub struct MakeSvc {
    pub context: Arc<MaintainServerContext>,
}

impl<T> Service<T> for MakeSvc {
    type Error = hyper::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;
    type Response = Svc;

    fn poll_ready(&mut self, _: &mut Context) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _: T) -> Self::Future {
        let context = self.context.clone();
        let fut = async move { Ok(Svc { context }) };
        Box::pin(fut)
    }
}
