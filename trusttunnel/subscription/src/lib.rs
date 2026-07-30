//! Client-side support for TrustTunnel endpoint subscriptions.

mod apply;
mod fetch;
mod response;
mod write;

pub use apply::apply_subscription;
pub use fetch::{
    fetch_for_config, fetch_subscription, fetch_subscription_json, HttpError, HttpRequest,
    HttpTransport, UreqTransport,
};
pub use response::SubscriptionResponse;
pub use write::replace_file_atomic;

#[derive(Debug)]
pub enum SubscriptionError {
    NoSubscription,
    InvalidDocument(String),
    Other(String),
}

impl std::fmt::Display for SubscriptionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SubscriptionError::NoSubscription => {
                write!(f, "No subscription URL configured.")
            }
            SubscriptionError::InvalidDocument(reason) => {
                write!(f, "Invalid subscription document: {reason}")
            }
            SubscriptionError::Other(message) => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for SubscriptionError {}
