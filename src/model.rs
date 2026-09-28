use serde::{Deserialize, Serialize};

/// The three credential names used in the PDF protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CredentialKind {
    PrimarySubscription,
    PartnerAccess,
    LeoAuth,
}

impl CredentialKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PrimarySubscription => "PrimarySubscription",
            Self::PartnerAccess => "PartnerAccess",
            Self::LeoAuth => "LeoAuth",
        }
    }
}

pub const UE: &str = "UE";
pub const PARTNER_NCC: &str = "Partner NCC";
pub const LEO_PARTNER: &str = "LEOPartner";
