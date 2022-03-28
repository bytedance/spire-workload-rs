use crate::spiffe::*;

pub trait SpiffeIdAuthorizer: Send + Sync + 'static {
    fn validate(&self, spiffe_id: SpiffeID) -> bool;

    fn validate_raw(&self, spiffe_id: &str) -> bool {
        let spiffe_id = spiffe_id.parse();

        if spiffe_id.is_err() {
            return false;
        }
        let spiffe_id = SpiffeID::new(spiffe_id.unwrap());
        if spiffe_id.is_err() {
            return false;
        }
        self.validate(spiffe_id.unwrap())
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
