//! Fetch live parameters for the imported endpoint's subscription.

use trusttunnel_settings::Endpoint;
use trusttunnel_subscription::{
    fetch_subscription, HttpRequest, HttpTransport, SubscriptionError, UreqTransport,
};

/// Fetch the candidate's subscription, apply the received parameters, and
/// stamp `last_fetched_at`. Fails with `SubscriptionError::NoSubscription`
/// when the candidate has no subscription URL. A failed fetch leaves the
/// candidate untouched; whether that is fatal is the caller's decision.
pub fn fetch_and_apply(candidate: &mut Endpoint) -> Result<(), SubscriptionError> {
    fetch_and_apply_with(candidate, &UreqTransport)
}

fn fetch_and_apply_with(
    candidate: &mut Endpoint,
    transport: &dyn HttpTransport,
) -> Result<(), SubscriptionError> {
    let Some(subscription) = &candidate.subscription else {
        return Err(SubscriptionError::NoSubscription);
    };
    let url = subscription.url.clone();
    let request = HttpRequest::for_endpoint(&url, candidate);
    let response = fetch_subscription(&request, transport)?;
    response.apply_to(candidate);
    if let Some(subscription) = &mut candidate.subscription {
        subscription.last_fetched_at = Some(utc_now_rfc3339());
    }
    Ok(())
}

fn utc_now_rfc3339() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use trusttunnel_subscription::HttpError;

    struct FakeTransport(Result<Vec<u8>, HttpError>);

    impl HttpTransport for FakeTransport {
        fn get(&self, _request: &HttpRequest) -> Result<Vec<u8>, HttpError> {
            match &self.0 {
                Ok(body) => Ok(body.clone()),
                Err(_) => Err(HttpError::Transport("simulated outage".to_string())),
            }
        }
    }

    fn body() -> Vec<u8> {
        serde_json::json!({
            "version": 1,
            "hostname": "live.example.com",
            "address": "5.6.7.8:443",
            "username": "live",
            "password": "live",
            "has_ipv6": true,
            "upstream_protocol": "http3",
            "anti_dpi": false,
            "skip_verification": false
        })
        .to_string()
        .into_bytes()
    }

    fn complete_candidate() -> trusttunnel_settings::Endpoint {
        trusttunnel_settings::Endpoint {
            hostname: "static.example.com".to_string(),
            addresses: vec!["1.1.1.1:443".to_string()],
            username: "static".to_string(),
            password: "static".to_string(),
            subscription: Some(trusttunnel_settings::EndpointSubscription {
                url: "https://u:p@static.example.com/subscription".to_string(),
                last_fetched_at: None,
            }),
            ..trusttunnel_settings::Endpoint::default()
        }
    }

    #[test]
    fn successful_fetch_applies_and_stamps_time() {
        let mut candidate = complete_candidate();
        fetch_and_apply_with(&mut candidate, &FakeTransport(Ok(body()))).unwrap();
        assert_eq!(candidate.hostname, "live.example.com");
        assert_eq!(candidate.username, "live");
        assert!(candidate
            .subscription
            .as_ref()
            .unwrap()
            .last_fetched_at
            .is_some());
    }

    #[test]
    fn no_subscription_returns_error_and_leaves_candidate_untouched() {
        let mut candidate = complete_candidate();
        candidate.subscription = None;
        let before = candidate.clone();
        let result = fetch_and_apply_with(&mut candidate, &FakeTransport(Ok(body())));
        assert!(matches!(result, Err(SubscriptionError::NoSubscription)));
        assert_eq!(candidate, before);
    }

    #[test]
    fn failed_fetch_returns_error_and_keeps_statics() {
        let mut candidate = complete_candidate();
        let result = fetch_and_apply_with(
            &mut candidate,
            &FakeTransport(Err(HttpError::Transport("down".to_string()))),
        );
        assert!(result.is_err());
        assert_eq!(candidate.hostname, "static.example.com");
        assert!(candidate
            .subscription
            .as_ref()
            .unwrap()
            .last_fetched_at
            .is_none());
    }
}
