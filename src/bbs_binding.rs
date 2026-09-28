//! Blind BBS+ issuance and nonce-bound presentations with variable credentialSubject attributes.
use crate::model::CredentialKind;
use ark_bls12_381::{Bls12_381, Fr, G1Affine};
use ark_ff::{PrimeField, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bbs_plus::{
    proof::{PoKOfSignatureG1Proof, PoKOfSignatureG1Protocol},
    setup::{KeypairG2, PublicKeyG2, SignatureParamsG1},
    signature::SignatureG1,
};
use dock_crypto_utils::signature::MessageOrBlinding;
use rand::{RngCore, rngs::OsRng};
use schnorr_pok::{
    compute_random_oracle_challenge,
    discrete_log::{PokPedersenCommitment, PokPedersenCommitmentProtocol},
};
use serde::Serialize;
use sha2::{Digest, Sha512};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Cursor,
    sync::{Mutex, OnceLock},
};
use thiserror::Error;

const PROTOCOL_LABEL: &[u8] = b"Cross-Constellation LEO BBS holder binding v1";
const ISSUANCE_LABEL: &[u8] = b"Cross-Constellation LEO BBS blind issuance v1";
const HOLDER_SECRET_LABEL: &[u8] = b"Cross-Constellation LEO identifier from DID key v1";
const PARAMETER_LABEL: &[u8] = b"Cross-Constellation LEO BBS+ parameters v1";
const HOLDER_SECRET_INDEX: usize = 0;
// The BBS+ message vector is deliberately limited to the always-hidden
// holder-binding identifier plus the paper's variable credentialSubject claims.
const FIRST_ATTRIBUTE_INDEX: usize = 1;
const NONCE_BYTES: usize = 32;

#[derive(Debug, Error)]
pub enum BbsBindingError {
    #[error("BBS+ cryptographic operation failed")]
    Crypto,
    #[error("presentation does not match its verifier request")]
    RequestMismatch,
    #[error("presentation proof is invalid")]
    InvalidProof,
    #[error("issuer rejected the holder commitment proof")]
    InvalidCommitmentProof,
    #[error("encoded cryptographic value is malformed")]
    Encoding,
    #[error("subject attribute input is invalid")]
    InvalidAttributes,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SubjectAttribute {
    pub name: String,
    pub value: String,
}

#[derive(Debug)]
pub struct Holder {
    did_key_material: [u8; NONCE_BYTES],
}
impl Holder {
    pub fn generate(_role: &'static str) -> Self {
        let mut key = [0; NONCE_BYTES];
        OsRng.fill_bytes(&mut key);
        Self {
            did_key_material: key,
        }
    }
    fn identifier_secret(&self) -> Fr {
        scalar_from_bytes(HOLDER_SECRET_LABEL, &self.did_key_material)
    }
}

#[derive(Debug)]
pub struct Issuer {
    pub role: &'static str,
    pub issuer_id: &'static str,
    attribute_count: usize,
    keypair: KeypairG2<Bls12_381>,
    params: SignatureParamsG1<Bls12_381>,
}
impl Issuer {
    pub fn generate_for_attributes(
        role: &'static str,
        issuer_id: &'static str,
        attribute_count: usize,
    ) -> Self {
        let params = parameters(attribute_count);
        Self {
            role,
            issuer_id,
            attribute_count,
            keypair: KeypairG2::generate_using_rng(&mut OsRng, &params),
            params,
        }
    }
    fn public_key(&self) -> &PublicKeyG2<Bls12_381> {
        &self.keypair.public_key
    }
}

#[derive(Debug)]
pub struct Credential {
    kind: CredentialKind,
    issuer_role: &'static str,
    issuer_id: &'static str,
    issuer_public_key: PublicKeyG2<Bls12_381>,
    signature: SignatureG1<Bls12_381>,
    identifier_commitment: String,
    subject_attributes: Vec<SubjectAttribute>,
    params: SignatureParamsG1<Bls12_381>,
}
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialArtifact<'a> {
    pub credential_type: &'static str,
    pub issuer: &'a str,
    pub issuer_id: &'a str,
    pub identifier_commitment: &'a str,
    pub credential_subject_attribute_count: usize,
    pub signature: String,
    pub cryptosuite: &'static str,
}
impl Credential {
    pub fn artifact(&self) -> Result<CredentialArtifact<'_>, BbsBindingError> {
        Ok(CredentialArtifact {
            credential_type: self.kind.as_str(),
            issuer: self.issuer_role,
            issuer_id: self.issuer_id,
            identifier_commitment: &self.identifier_commitment,
            credential_subject_attribute_count: self.subject_attributes.len(),
            signature: encode(&self.signature)?,
            cryptosuite: "BBS+-BLS12-381-SHA-512",
        })
    }
    pub fn attribute_count(&self) -> usize {
        self.subject_attributes.len()
    }
}

#[derive(Debug, Clone)]
pub struct VerifierRequest {
    pub verifier: &'static str,
    pub credential_kind: CredentialKind,
    nonce: [u8; NONCE_BYTES],
}
impl VerifierRequest {
    pub fn generate(verifier: &'static str, credential_kind: CredentialKind) -> Self {
        let mut nonce = [0; NONCE_BYTES];
        OsRng.fill_bytes(&mut nonce);
        Self {
            verifier,
            credential_kind,
            nonce,
        }
    }
}
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Presentation {
    pub credential_type: CredentialKind,
    pub issuer: String,
    pub issuer_id: String,
    pub verifier: String,
    pub nonce: String,
    pub credential_subject_attribute_count: usize,
    /// Values are keyed by the fixed credentialSubject schema index.  The attribute
    /// name is deliberately not serialized again in every VP: `attr_01`, `attr_02`,
    /// ... are reconstructed from this schema index during verification.
    pub revealed_attribute_values: BTreeMap<usize, String>,
    pub proof: String,
    pub cryptosuite: String,
}

pub fn blind_issue(
    issuer: &Issuer,
    holder: &Holder,
    kind: CredentialKind,
    attributes: &[SubjectAttribute],
) -> Result<Credential, BbsBindingError> {
    validate_attributes(attributes)?;
    if issuer.attribute_count != attributes.len() {
        return Err(BbsBindingError::InvalidAttributes);
    }
    let nonce = random_nonce();
    let holder_secret = holder.identifier_secret();
    let blinding = Fr::rand(&mut OsRng);
    let commitment = issuer
        .params
        .commit_to_messages([(HOLDER_SECRET_INDEX, &holder_secret)], &blinding)
        .map_err(|_| BbsBindingError::Crypto)?;
    let protocol = PokPedersenCommitmentProtocol::init(
        holder_secret,
        Fr::rand(&mut OsRng),
        &issuer.params.h[HOLDER_SECRET_INDEX],
        blinding,
        Fr::rand(&mut OsRng),
        &issuer.params.h_0,
    );
    let challenge = issuance_challenge(&protocol, &commitment, issuer, kind, &nonce)?;
    let proof = protocol.gen_proof(&challenge);
    let verifier_challenge = issuance_proof_challenge(&proof, &commitment, issuer, kind, &nonce)?;
    if !proof.verify(
        &commitment,
        &issuer.params.h[HOLDER_SECRET_INDEX],
        &issuer.params.h_0,
        &verifier_challenge,
    ) {
        return Err(BbsBindingError::InvalidCommitmentProof);
    }
    let messages = credential_messages(holder, attributes);
    let mut clear = BTreeMap::new();
    for index in FIRST_ATTRIBUTE_INDEX..messages.len() {
        clear.insert(index, &messages[index]);
    }
    let blind_signature = SignatureG1::<Bls12_381>::new_with_committed_messages(
        &mut OsRng,
        &commitment,
        clear,
        &issuer.keypair.secret_key,
        &issuer.params,
    )
    .map_err(|_| BbsBindingError::Crypto)?;
    let signature = blind_signature.unblind(&blinding);
    signature
        .verify(
            &messages,
            issuer.public_key().clone(),
            issuer.params.clone(),
        )
        .map_err(|_| BbsBindingError::InvalidProof)?;
    Ok(Credential {
        kind,
        issuer_role: issuer.role,
        issuer_id: issuer.issuer_id,
        issuer_public_key: issuer.public_key().clone(),
        signature,
        identifier_commitment: encode(&commitment)?,
        subject_attributes: attributes.to_vec(),
        params: issuer.params.clone(),
    })
}

/// Generates a fresh proof. The holder-binding message remains hidden regardless of disclosure ratio.
pub fn present(
    credential: &Credential,
    holder: &Holder,
    request: &VerifierRequest,
    reveal_indices: &[usize],
) -> Result<Presentation, BbsBindingError> {
    if credential.kind != request.credential_kind {
        return Err(BbsBindingError::RequestMismatch);
    }
    let reveal = normalize_reveal_indices(credential.attribute_count(), reveal_indices)?;
    let messages = credential_messages(holder, &credential.subject_attributes);
    let mut proof_inputs = Vec::with_capacity(messages.len());
    for (index, message) in messages.iter().enumerate() {
        let is_revealed = index
            .checked_sub(FIRST_ATTRIBUTE_INDEX)
            .is_some_and(|i| reveal.contains(&i));
        proof_inputs.push(if is_revealed {
            MessageOrBlinding::RevealMessage(message)
        } else {
            MessageOrBlinding::BlindMessageRandomly(message)
        });
    }
    let protocol = PoKOfSignatureG1Protocol::<Bls12_381>::init(
        &mut OsRng,
        &credential.signature,
        &credential.params,
        proof_inputs,
    )
    .map_err(|_| BbsBindingError::Crypto)?;
    let revealed_attribute_values = reveal
        .iter()
        .map(|i| (*i, credential.subject_attributes[*i].value.clone()))
        .collect::<BTreeMap<_, _>>();
    let challenge =
        presentation_challenge(&protocol, request, credential, &revealed_attribute_values)?;
    let proof = protocol
        .gen_proof(&challenge)
        .map_err(|_| BbsBindingError::Crypto)?;
    Ok(Presentation {
        credential_type: credential.kind,
        issuer: credential.issuer_role.to_string(),
        issuer_id: credential.issuer_id.to_string(),
        verifier: request.verifier.to_string(),
        nonce: URL_SAFE_NO_PAD.encode(request.nonce),
        credential_subject_attribute_count: credential.attribute_count(),
        revealed_attribute_values,
        proof: encode(&proof)?,
        cryptosuite: "BBS+-BLS12-381-SHA-512".to_string(),
    })
}

pub fn verify(
    presentation: &Presentation,
    request: &VerifierRequest,
    issuer: &Issuer,
) -> Result<(), BbsBindingError> {
    if presentation.credential_type != request.credential_kind
        || presentation.verifier != request.verifier
        || presentation.nonce != URL_SAFE_NO_PAD.encode(request.nonce)
        || presentation.issuer_id != issuer.issuer_id
        || presentation.issuer != issuer.role
        || presentation.credential_subject_attribute_count != issuer.attribute_count
    {
        return Err(BbsBindingError::RequestMismatch);
    }
    validate_revealed_attribute_values(
        presentation.credential_subject_attribute_count,
        &presentation.revealed_attribute_values,
    )?;
    let proof = decode::<PoKOfSignatureG1Proof<Bls12_381>>(&presentation.proof)?;
    let challenge = proof_challenge(
        &proof,
        request,
        presentation.credential_type,
        issuer.issuer_id,
        issuer.public_key(),
        presentation.credential_subject_attribute_count,
        &presentation.revealed_attribute_values,
    )?;
    proof
        .verify(
            &revealed_messages(
                presentation.credential_subject_attribute_count,
                &presentation.revealed_attribute_values,
            )?,
            &challenge,
            issuer.public_key().clone(),
            issuer.params.clone(),
        )
        .map_err(|_| BbsBindingError::InvalidProof)
}

fn parameters(attribute_count: usize) -> SignatureParamsG1<Bls12_381> {
    static CACHE: OnceLock<Mutex<BTreeMap<usize, SignatureParamsG1<Bls12_381>>>> = OnceLock::new();
    let mut cache = CACHE
        .get_or_init(|| Mutex::new(BTreeMap::new()))
        .lock()
        .expect("parameter cache mutex poisoned");
    cache
        .entry(attribute_count)
        .or_insert_with(|| {
            SignatureParamsG1::new::<Sha512>(
                PARAMETER_LABEL,
                (FIRST_ATTRIBUTE_INDEX + attribute_count) as u32,
            )
        })
        .clone()
}
fn credential_messages(holder: &Holder, attributes: &[SubjectAttribute]) -> Vec<Fr> {
    let mut values = vec![holder.identifier_secret()];
    values.extend(attributes.iter().map(attribute_scalar));
    values
}
fn revealed_messages(
    count: usize,
    attributes: &BTreeMap<usize, String>,
) -> Result<BTreeMap<usize, Fr>, BbsBindingError> {
    let mut values = BTreeMap::new();
    for (index, value) in attributes {
        if *index >= count || value.is_empty() {
            return Err(BbsBindingError::InvalidAttributes);
        }
        values.insert(
            FIRST_ATTRIBUTE_INDEX + index,
            attribute_scalar_by_index(*index, value),
        );
    }
    Ok(values)
}
fn normalize_reveal_indices(
    count: usize,
    input: &[usize],
) -> Result<BTreeSet<usize>, BbsBindingError> {
    let values = input.iter().copied().collect::<BTreeSet<_>>();
    if values.len() != input.len() || values.iter().any(|i| *i >= count) {
        return Err(BbsBindingError::InvalidAttributes);
    }
    Ok(values)
}
fn validate_attributes(attributes: &[SubjectAttribute]) -> Result<(), BbsBindingError> {
    for (index, attribute) in attributes.iter().enumerate() {
        if attribute.value.is_empty()
            || attribute_index(&attribute.name, attributes.len())? != index
        {
            return Err(BbsBindingError::InvalidAttributes);
        }
    }
    Ok(())
}
fn validate_revealed_attribute_values(
    count: usize,
    attributes: &BTreeMap<usize, String>,
) -> Result<(), BbsBindingError> {
    if attributes
        .iter()
        .any(|(index, value)| *index >= count || value.is_empty())
    {
        return Err(BbsBindingError::InvalidAttributes);
    }
    Ok(())
}
fn attribute_index(name: &str, count: usize) -> Result<usize, BbsBindingError> {
    name.strip_prefix("attr_")
        .and_then(|v| v.parse::<usize>().ok())
        .and_then(|v| v.checked_sub(1))
        .filter(|i| *i < count)
        .ok_or(BbsBindingError::InvalidAttributes)
}
fn attribute_scalar(attribute: &SubjectAttribute) -> Fr {
    attribute_scalar_by_index(
        attribute_index(&attribute.name, usize::MAX)
            .expect("credential attributes are validated before signing"),
        &attribute.value,
    )
}
fn attribute_scalar_by_index(index: usize, value: &str) -> Fr {
    let mut encoded = Vec::new();
    append(&mut encoded, format!("attr_{:02}", index + 1).as_bytes());
    append(&mut encoded, value.as_bytes());
    scalar_from_bytes(
        b"Cross-Constellation LEO credentialSubject attribute",
        &encoded,
    )
}
fn presentation_challenge(
    protocol: &PoKOfSignatureG1Protocol<Bls12_381>,
    request: &VerifierRequest,
    credential: &Credential,
    revealed: &BTreeMap<usize, String>,
) -> Result<Fr, BbsBindingError> {
    let mut transcript = presentation_transcript(
        request,
        credential.kind,
        credential.issuer_id,
        &credential.issuer_public_key,
        credential.attribute_count(),
    )?;
    PoKOfSignatureG1Protocol::compute_challenge_contribution(
        &protocol.A_prime,
        &protocol.A_bar,
        &protocol.d,
        &protocol.sc_comm_1.t,
        &protocol.sc_comm_2.t,
        &revealed_messages(credential.attribute_count(), revealed)?,
        &credential.params,
        &mut transcript,
    )
    .map_err(|_| BbsBindingError::Crypto)?;
    Ok(compute_random_oracle_challenge::<Fr, Sha512>(&transcript))
}
fn proof_challenge(
    proof: &PoKOfSignatureG1Proof<Bls12_381>,
    request: &VerifierRequest,
    kind: CredentialKind,
    issuer_id: &str,
    public_key: &PublicKeyG2<Bls12_381>,
    count: usize,
    revealed: &BTreeMap<usize, String>,
) -> Result<Fr, BbsBindingError> {
    let mut transcript = presentation_transcript(request, kind, issuer_id, public_key, count)?;
    proof
        .challenge_contribution(
            &revealed_messages(count, revealed)?,
            &parameters(count),
            &mut transcript,
        )
        .map_err(|_| BbsBindingError::InvalidProof)?;
    Ok(compute_random_oracle_challenge::<Fr, Sha512>(&transcript))
}
fn issuance_challenge(
    protocol: &PokPedersenCommitmentProtocol<G1Affine>,
    commitment: &G1Affine,
    issuer: &Issuer,
    kind: CredentialKind,
    nonce: &[u8; NONCE_BYTES],
) -> Result<Fr, BbsBindingError> {
    let mut transcript = issuance_transcript(issuer, kind, nonce)?;
    protocol
        .challenge_contribution(
            &issuer.params.h[HOLDER_SECRET_INDEX],
            &issuer.params.h_0,
            commitment,
            &mut transcript,
        )
        .map_err(|_| BbsBindingError::Crypto)?;
    Ok(compute_random_oracle_challenge::<Fr, Sha512>(&transcript))
}
fn issuance_proof_challenge(
    proof: &PokPedersenCommitment<G1Affine>,
    commitment: &G1Affine,
    issuer: &Issuer,
    kind: CredentialKind,
    nonce: &[u8; NONCE_BYTES],
) -> Result<Fr, BbsBindingError> {
    let mut transcript = issuance_transcript(issuer, kind, nonce)?;
    proof
        .challenge_contribution(
            &issuer.params.h[HOLDER_SECRET_INDEX],
            &issuer.params.h_0,
            commitment,
            &mut transcript,
        )
        .map_err(|_| BbsBindingError::InvalidCommitmentProof)?;
    Ok(compute_random_oracle_challenge::<Fr, Sha512>(&transcript))
}
fn presentation_transcript(
    request: &VerifierRequest,
    kind: CredentialKind,
    issuer_id: &str,
    public_key: &PublicKeyG2<Bls12_381>,
    count: usize,
) -> Result<Vec<u8>, BbsBindingError> {
    let mut t = Vec::new();
    append(&mut t, PROTOCOL_LABEL);
    append(&mut t, kind.as_str().as_bytes());
    append(&mut t, issuer_id.as_bytes());
    append(&mut t, &(count as u64).to_be_bytes());
    append(&mut t, &canonical_bytes(public_key)?);
    append(&mut t, request.verifier.as_bytes());
    append(&mut t, &request.nonce);
    Ok(t)
}
fn issuance_transcript(
    issuer: &Issuer,
    kind: CredentialKind,
    nonce: &[u8; NONCE_BYTES],
) -> Result<Vec<u8>, BbsBindingError> {
    let mut t = Vec::new();
    append(&mut t, ISSUANCE_LABEL);
    append(&mut t, kind.as_str().as_bytes());
    append(&mut t, issuer.issuer_id.as_bytes());
    append(&mut t, &(issuer.attribute_count as u64).to_be_bytes());
    append(&mut t, &canonical_bytes(issuer.public_key())?);
    append(&mut t, nonce);
    Ok(t)
}
fn append(target: &mut Vec<u8>, value: &[u8]) {
    target.extend_from_slice(&(value.len() as u64).to_be_bytes());
    target.extend_from_slice(value);
}
fn scalar_from_bytes(label: &[u8], value: &[u8]) -> Fr {
    let mut hash = Sha512::new();
    append_hash(&mut hash, label);
    append_hash(&mut hash, value);
    Fr::from_le_bytes_mod_order(&hash.finalize())
}
fn append_hash(hash: &mut Sha512, value: &[u8]) {
    hash.update((value.len() as u64).to_be_bytes());
    hash.update(value);
}
fn random_nonce() -> [u8; NONCE_BYTES] {
    let mut nonce = [0; NONCE_BYTES];
    OsRng.fill_bytes(&mut nonce);
    nonce
}
fn encode<T: CanonicalSerialize>(value: &T) -> Result<String, BbsBindingError> {
    Ok(URL_SAFE_NO_PAD.encode(canonical_bytes(value)?))
}
fn canonical_bytes<T: CanonicalSerialize>(value: &T) -> Result<Vec<u8>, BbsBindingError> {
    let mut bytes = Vec::new();
    value
        .serialize_compressed(&mut bytes)
        .map_err(|_| BbsBindingError::Encoding)?;
    Ok(bytes)
}
fn decode<T: CanonicalDeserialize>(value: &str) -> Result<T, BbsBindingError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| BbsBindingError::Encoding)?;
    let mut cursor = Cursor::new(bytes.as_slice());
    let result = T::deserialize_compressed(&mut cursor).map_err(|_| BbsBindingError::Encoding)?;
    if cursor.position() != bytes.len() as u64 {
        return Err(BbsBindingError::Encoding);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn attributes(count: usize) -> Vec<SubjectAttribute> {
        (1..=count)
            .map(|i| SubjectAttribute {
                name: format!("attr_{i:02}"),
                value: format!("value-{i:02}-fixed-length-payload"),
            })
            .collect()
    }
    #[test]
    fn attributes_are_selectively_disclosed() {
        let issuer = Issuer::generate_for_attributes("Partner NCC", "did:web:partner-ncc.com", 7);
        let holder = Holder::generate("UE");
        let c = blind_issue(
            &issuer,
            &holder,
            CredentialKind::PartnerAccess,
            &attributes(7),
        )
        .unwrap();
        let r = VerifierRequest::generate("LEOPartner", CredentialKind::PartnerAccess);
        let p = present(&c, &holder, &r, &[0, 2, 5]).unwrap();
        assert_eq!(p.revealed_attribute_values.len(), 3);
        assert!(p.revealed_attribute_values.contains_key(&0));
        verify(&p, &r, &issuer).unwrap();
    }
    #[test]
    fn identifier_is_hidden_and_nonce_bound() {
        let issuer = Issuer::generate_for_attributes("Primary NCC", "did:web:primary-ncc.com", 5);
        let holder = Holder::generate("UE");
        let c = blind_issue(
            &issuer,
            &holder,
            CredentialKind::PrimarySubscription,
            &attributes(5),
        )
        .unwrap();
        assert!(!c.artifact().unwrap().identifier_commitment.contains("did:"));
        let r = VerifierRequest::generate("LEOPrimary", CredentialKind::PrimarySubscription);
        let p = present(&c, &holder, &r, &[0, 1, 2, 3]).unwrap();
        verify(&p, &r, &issuer).unwrap();
        let replay = VerifierRequest::generate("LEOPrimary", CredentialKind::PrimarySubscription);
        assert!(verify(&p, &replay, &issuer).is_err());
    }
}
