use std::collections::BTreeMap;

use did_method_key::DIDKey;
use serde_json::{Value, json};
use ssi_dids_core::{DID, DIDResolver, document::representation, resolution};

use crate::error::DynError;

pub struct OfflineDidResolver {
    did_web_cache: BTreeMap<String, Vec<u8>>,
    did_key: DIDKey,
}

impl OfflineDidResolver {
    pub fn new<const N: usize>(entries: [(String, Vec<u8>); N]) -> Self {
        Self {
            did_web_cache: BTreeMap::from(entries),
            did_key: DIDKey,
        }
    }
}

impl DIDResolver for OfflineDidResolver {
    async fn resolve_representation<'a>(
        &'a self,
        did: &'a DID,
        options: resolution::Options,
    ) -> Result<resolution::Output<Vec<u8>>, resolution::Error> {
        match did.method_name() {
            // did:web normally dereferences HTTPS resources. The experiment
            // intentionally models an already-synced onboard cache instead.
            "web" => self
                .did_web_cache
                .get(did.as_str())
                .cloned()
                .map(|bytes| {
                    resolution::Output::from_content(
                        bytes,
                        Some(representation::MediaType::Json.name().to_string()),
                    )
                })
                .ok_or(resolution::Error::NotFound),
            "key" => self.did_key.resolve_representation(did, options).await,
            other => Err(resolution::Error::MethodNotSupported(other.to_string())),
        }
    }
}

pub fn did_web_document(did: &DID, public_key_multibase: &str) -> Value {
    let vm_id = format!("{did}#key-1");
    json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/multikey/v1"
        ],
        "id": did.to_string(),
        "verificationMethod": [{
            "id": vm_id,
            "type": "Multikey",
            "controller": did.to_string(),
            "publicKeyMultibase": public_key_multibase
        }],
        "assertionMethod": [vm_id],
        "authentication": [format!("{did}#key-1")]
    })
}

pub fn public_key_multibase(did_key: &DID) -> Result<&str, DynError> {
    did_key
        .as_str()
        .strip_prefix("did:key:")
        .ok_or_else(|| "expected did:key identifier".into())
}
