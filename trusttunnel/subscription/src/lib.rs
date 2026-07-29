//! Client-side support for TrustTunnel endpoint subscriptions.

mod fetch;
mod response;

pub use fetch::{HttpError, HttpRequest, HttpTransport, UreqTransport};
pub use response::SubscriptionResponse;

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
