use super::*;

impl LocalVault {
    /// Two touches. The callback runs after credential creation and before
    /// confirmation, so shells can update their prompt for the second touch.
    pub fn enroll_hardware_key(
        &self,
        label: String,
        on_credential_created: &dyn Fn(),
    ) -> LocalResult<HardwareKey> {
        let master_key = self.root_key()?;
        let pending = RememberedUnlockStore::begin_enroll(self.authenticator.as_ref(), &label)
            .map_err(unlock_error)?;
        on_credential_created();
        self.check_enrollment_session(&master_key)?;
        let mut remembered = self.load_remembered()?;
        let entry = remembered
            .confirm_enroll(
                self.authenticator.as_ref(),
                pending,
                master_key.as_bytes(),
                chrono::Utc::now().to_rfc3339(),
            )
            .map_err(unlock_error)?;
        // Lock may have happened while waiting for either touch. Never publish
        // an enrollment belonging to that previous unlocked session.
        let current = self.device_key.lock().expect("lock poisoned");
        if !current
            .as_ref()
            .is_some_and(|key| Arc::ptr_eq(key, &master_key))
        {
            return Err(LocalError::Locked);
        }
        remembered.unlock_source = UnlockSource::HardwareKey;
        self.save_remembered(&remembered)?;
        Ok(HardwareKey {
            label: entry.label,
            credential_id: entry.credential_id,
            enrolled_at: entry.enrolled_at,
        })
    }

    fn check_enrollment_session(&self, expected: &Arc<SecretKey>) -> LocalResult<()> {
        if Arc::ptr_eq(&self.root_key()?, expected) {
            Ok(())
        } else {
            Err(LocalError::Locked)
        }
    }
}
