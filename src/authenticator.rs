use crate::spiffe::*;

pub trait SpiffeIdAuthorizer: Send + Sync + 'static {
    fn validate(&self, spiffe_id: SpiffeID) -> bool;

    fn validate_raw(&self, spiffe_id: &str) -> bool {
        if let Ok(spiffe_id) = spiffe_id.parse() {
            if let Ok(id) = SpiffeID::new(spiffe_id) {
                return self.validate(id);
            }
        }
        false
    }
}

impl SpiffeIdAuthorizer for bool {
    fn validate(&self, _spiffe_id: SpiffeID) -> bool {
        *self
    }
}

impl SpiffeIdAuthorizer for SpiffeID {
    fn validate(&self, spiffe_id: SpiffeID) -> bool {
        &spiffe_id == self
    }
}

impl SpiffeIdAuthorizer for fn(SpiffeID) -> bool {
    fn validate(&self, spiffe_id: SpiffeID) -> bool {
        self(spiffe_id)
    }
}

impl SpiffeIdAuthorizer for SpiffeIDMatcher {
    fn validate(&self, spiffe_id: SpiffeID) -> bool {
        self.matches(&spiffe_id)
    }
}
