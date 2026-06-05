use serde::Serialize;
use ssi_claims::{
    SignatureEnvironment, VerificationParameters,
    vc::{
        syntax::NonEmptyVec,
        v2::syntax::{JsonCredential, JsonPresentation},
    },
};
use ssi_data_integrity::{
    AnyDataIntegrity, AnyInputSuiteOptions, AnySelectionOptions, AnySignatureOptions, AnySuite,
    CryptographicSuite, JsonPointerBuf, ProofOptions as SuiteOptions,
};
use ssi_dids_core::{DID, DIDResolver, VerificationMethodDIDResolver};
use ssi_jwk::JWK;
use ssi_verification_methods::AnyMethod;
use ssi_verification_methods_core::{ProofPurpose, ReferenceOrOwned, SingleSecretSigner};

use crate::{did_cache::OfflineDidResolver, error::DynError};

pub type DerivedDocument = ssi_json_ld::syntax::Object;

pub async fn issue_bbs_vc<S: Serialize + Clone>(
    resolver: &VerificationMethodDIDResolver<OfflineDidResolver, AnyMethod>,
    issuer_key: &JWK,
    issuer_did: &DID,
    credential_id: &str,
    subject: S,
    created: &str,
) -> Result<AnyDataIntegrity<JsonCredential<S>>, DynError> {
    let mut unsigned_vc = JsonCredential::<S>::new(
        Some(credential_id.parse()?),
        issuer_did.to_owned().into_uri().into(),
        NonEmptyVec::new(subject),
    );
    unsigned_vc.valid_from = Some(created.parse()?);

    let issuer_verification_method = resolver
        .resolve_into_any_verification_method(issuer_did)
        .await?
        .ok_or("issuer DID document has no verification method")?;
    let issuer_verification_method_ref =
        ReferenceOrOwned::Reference(issuer_verification_method.id.into());

    let mut signature_options = AnySignatureOptions::default();
    signature_options.mandatory_pointers = vc2_mandatory_pointers()?;

    let proof_options = SuiteOptions::new(
        created.parse()?,
        issuer_verification_method_ref,
        ProofPurpose::Assertion,
        AnyInputSuiteOptions::default(),
    );

    let signer = SingleSecretSigner::new(issuer_key.clone()).into_local();
    AnySuite::Bbs2023
        .sign_with(
            SignatureEnvironment::default(),
            unsigned_vc,
            resolver,
            &signer,
            proof_options,
            signature_options,
        )
        .await
        .map_err(Into::into)
}

pub async fn sign_holder_vp(
    resolver: &VerificationMethodDIDResolver<OfflineDidResolver, AnyMethod>,
    holder_key: &JWK,
    holder_did: &DID,
    presentation: JsonPresentation<AnyDataIntegrity>,
    created: &str,
) -> Result<AnyDataIntegrity<JsonPresentation<AnyDataIntegrity>>, DynError> {
    let holder_verification_method = resolver
        .resolve_into_any_verification_method(holder_did)
        .await?
        .ok_or("holder DID document has no verification method")?;
    let holder_verification_method_ref =
        ReferenceOrOwned::Reference(holder_verification_method.id.into());

    let proof_options = SuiteOptions::new(
        created.parse()?,
        holder_verification_method_ref,
        ProofPurpose::Authentication,
        AnyInputSuiteOptions::default(),
    );

    let signer = SingleSecretSigner::new(holder_key.clone()).into_local();

    // The embedded VCs remain BBS+ bbs-2023 derived credentials. The VP proof
    // is a holder-authentication proof: it shows the presenter controls the
    // DID in `holder` / `credentialSubject.id`.
    AnySuite::Ed25519Signature2020
        .sign(presentation, resolver, &signer, proof_options)
        .await
        .map_err(Into::into)
}

pub async fn derive_roaming_contract<T>(
    base_vc: &AnyDataIntegrity<T>,
    verification_params: &VerificationParameters<
        &VerificationMethodDIDResolver<OfflineDidResolver, AnyMethod>,
    >,
) -> Result<AnyDataIntegrity<DerivedDocument>, DynError>
where
    T: Serialize + ssi_json_ld::JsonLdNodeObject + ssi_json_ld::Expandable,
    T::Expanded<ssi_data_integrity::ssi_rdf::LexicalInterpretation, ()>:
        Into<ssi_json_ld::ExpandedDocument>,
{
    derive_with_selective_pointers(
        base_vc,
        verification_params,
        &[
            "/credentialSubject/https:~1~1example.org~1leo#roamingContractId",
            "/credentialSubject/https:~1~1example.org~1leo#requester",
            "/credentialSubject/https:~1~1example.org~1leo#homeOperator",
            "/credentialSubject/https:~1~1example.org~1leo#visitedOperator",
            "/credentialSubject/https:~1~1example.org~1leo#authorizedFor",
        ],
        b"leo-vc-roaming-derived-vp",
    )
    .await
}

pub async fn derive_cooperation_agreement<T>(
    base_vc: &AnyDataIntegrity<T>,
    verification_params: &VerificationParameters<
        &VerificationMethodDIDResolver<OfflineDidResolver, AnyMethod>,
    >,
) -> Result<AnyDataIntegrity<DerivedDocument>, DynError>
where
    T: Serialize + ssi_json_ld::JsonLdNodeObject + ssi_json_ld::Expandable,
    T::Expanded<ssi_data_integrity::ssi_rdf::LexicalInterpretation, ()>:
        Into<ssi_json_ld::ExpandedDocument>,
{
    derive_with_selective_pointers(
        base_vc,
        verification_params,
        &[
            "/credentialSubject/https:~1~1example.org~1leo#partner",
            "/credentialSubject/https:~1~1example.org~1leo#agreementId",
            "/credentialSubject/https:~1~1example.org~1leo#scope",
        ],
        b"leo-vc-cooperation-derived-vp",
    )
    .await
}

pub async fn derive_leo_authorization<T>(
    base_vc: &AnyDataIntegrity<T>,
    verification_params: &VerificationParameters<
        &VerificationMethodDIDResolver<OfflineDidResolver, AnyMethod>,
    >,
) -> Result<AnyDataIntegrity<DerivedDocument>, DynError>
where
    T: Serialize + ssi_json_ld::JsonLdNodeObject + ssi_json_ld::Expandable,
    T::Expanded<ssi_data_integrity::ssi_rdf::LexicalInterpretation, ()>:
        Into<ssi_json_ld::ExpandedDocument>,
{
    // The satellite DID itself is mandatory in the base proof. The derived
    // presentation additionally reveals the operator and satellite label that
    // the peer LEO needs for local authorization. statusListIndex is omitted
    // because revocation/status-list checks are outside this experiment.
    derive_with_selective_pointers(
        base_vc,
        verification_params,
        &[
            "/credentialSubject/https:~1~1example.org~1leo#operator",
            "/credentialSubject/https:~1~1example.org~1leo#satelliteId",
            "/credentialSubject/https:~1~1example.org~1leo#cooperationAgreementId",
        ],
        b"leo-vc-auth-derived-vp",
    )
    .await
}

async fn derive_with_selective_pointers<T>(
    base_vc: &AnyDataIntegrity<T>,
    verification_params: &VerificationParameters<
        &VerificationMethodDIDResolver<OfflineDidResolver, AnyMethod>,
    >,
    pointers: &[&str],
    presentation_header: &[u8],
) -> Result<AnyDataIntegrity<DerivedDocument>, DynError>
where
    T: Serialize + ssi_json_ld::JsonLdNodeObject + ssi_json_ld::Expandable,
    T::Expanded<ssi_data_integrity::ssi_rdf::LexicalInterpretation, ()>:
        Into<ssi_json_ld::ExpandedDocument>,
{
    let mut selection_options = AnySelectionOptions::default();
    selection_options.selective_pointers = pointers
        .iter()
        .map(|pointer| json_pointer(pointer))
        .collect::<Result<_, _>>()?;
    selection_options.presentation_header = Some(presentation_header.to_vec());

    base_vc
        .select(verification_params, selection_options)
        .await
        .map_err(Into::into)
}

fn vc2_mandatory_pointers() -> Result<Vec<JsonPointerBuf>, DynError> {
    Ok(vec![
        json_pointer("/@context")?,
        json_pointer("/id")?,
        json_pointer("/type")?,
        json_pointer("/issuer")?,
        json_pointer("/validFrom")?,
        json_pointer("/credentialSubject/id")?,
    ])
}

fn json_pointer(value: &str) -> Result<JsonPointerBuf, DynError> {
    value.parse().map_err(Into::into)
}
