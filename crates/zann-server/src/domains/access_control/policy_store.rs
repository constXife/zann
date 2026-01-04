use std::sync::{Arc, RwLock};

use crate::domains::access_control::policies::PolicySet;

#[derive(Clone)]
pub struct PolicyStore {
    inner: Arc<RwLock<PolicySet>>,
}

impl PolicyStore {
    #[must_use]
    pub fn new(set: PolicySet) -> Self {
        Self {
            inner: Arc::new(RwLock::new(set)),
        }
    }

    #[must_use]
    pub fn get(&self) -> PolicySet {
        self.inner
            .read()
            .unwrap_or_else(|err| err.into_inner())
            .clone()
    }

    pub fn set(&self, set: PolicySet) {
        let mut guard = self.inner.write().unwrap_or_else(|err| err.into_inner());
        *guard = set;
    }
}
