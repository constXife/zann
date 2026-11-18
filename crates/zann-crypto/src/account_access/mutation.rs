use super::*;
use crate::signatures::verify_ed25519;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationPurpose {
    GrantAdd,
    GrantReplace,
    GrantRemove,
    CodeRotate,
    CredentialAdd,
    CredentialRevoke,
    CredentialMode,
}
impl MutationPurpose {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::GrantAdd => "grant_add",
            Self::GrantReplace => "grant_replace",
            Self::GrantRemove => "grant_remove",
            Self::CodeRotate => "code_rotate",
            Self::CredentialAdd => "credential_add",
            Self::CredentialRevoke => "credential_revoke",
            Self::CredentialMode => "credential_mode",
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Authority {
    Session,
    Recovery,
}
impl Authority {
    fn as_str(self) -> &'static str {
        match self {
            Self::Session => "session",
            Self::Recovery => "recovery",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MutationContext {
    pub server_id: String,
    pub user_id: Uuid,
    pub authority: Authority,
    pub authority_id: Uuid,
    pub security_revision: u64,
    pub nonce: String,
    pub purpose: MutationPurpose,
    pub body_digest: String,
}
impl MutationContext {
    fn transcript(&self) -> Result<Transcript> {
        if self.security_revision == 0
            || !valid_server_id(&self.server_id)
            || self.user_id.is_nil()
            || self.authority_id.is_nil()
        {
            return Err(AccountAccessError::Invalid("mutation authority"));
        }
        Ok(Transcript::new("zann account mutation v1")
            .field(self.server_id.as_bytes())
            .field(self.user_id.as_bytes())
            .field(self.authority.as_str().as_bytes())
            .field(self.authority_id.as_bytes())
            .field(&self.security_revision.to_be_bytes())
            .field(&array::<32>(&self.nonce)?)
            .field(self.purpose.as_str().as_bytes())
            .field(&array::<32>(&self.body_digest)?))
    }
    pub fn verify(&self, descriptor: &AccountDescriptor, signature: &str) -> Result<()> {
        descriptor.validate()?;
        if self.server_id != descriptor.server_id
            || self.user_id != descriptor.user_id
            || !verify_ed25519(
                &array::<32>(&descriptor.proof_public_key)?,
                self.transcript()?.bytes(),
                &array::<64>(signature)?,
            )
        {
            return Err(AccountAccessError::Invalid("mutation signature"));
        }
        Ok(())
    }
}
impl AccountCustody {
    pub fn sign_mutation(
        &self,
        descriptor: &AccountDescriptor,
        context: &MutationContext,
    ) -> Result<String> {
        self.proves(descriptor)?;
        if descriptor.server_id != context.server_id || descriptor.user_id != context.user_id {
            return Err(AccountAccessError::Invalid("mutation subject"));
        }
        Ok(encode(&self.0.sign(context.transcript()?.bytes())))
    }
}
