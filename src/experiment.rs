use std::{
    collections::HashSet,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::Serialize;
use serde_json::json;
use ssi_claims::{
    VerificationParameters,
    vc::v2::syntax::{JsonCredential, JsonPresentation},
};
use ssi_data_integrity::AnyDataIntegrity;
use ssi_dids_core::{DIDBuf, VerificationMethodDIDResolver};
use ssi_verification_methods::AnyMethod;

use crate::{
    did_cache::{OfflineDidResolver, did_web_document, public_key_multibase},
    error::DynError,
    fs_util::{ensure_dir, file_len, workspace_path, write_json, write_text},
    metrics::{StageMetric, StageTimer},
    model::{
        CooperationAgreementSubject, LeoAuthorizationSubject, QemuProfile, RoamingContractSubject,
        SubjectKeys, qemu_profile,
    },
    vc::{
        derive_cooperation_agreement, derive_leo_authorization, derive_roaming_contract,
        issue_bbs_vc, sign_holder_vp,
    },
};

const RESULTS_ROOT: &str = "results";
const DID_CACHE_ROOT: &str = "fixtures/did-cache";

#[derive(Debug)]
struct ExperimentState {
    run_id: String,
    result_dir: PathBuf,
    artifact_dir: PathBuf,
    did_cache_dir: PathBuf,
    metrics: Vec<StageMetric>,
    seen_actors: HashSet<&'static str>,
    process_cold_start_recorded: bool,
}

#[derive(Debug, Clone, Serialize)]
struct ExperimentSummary {
    run_id: String,
    qemu_profile: QemuProfile,
    metrics: Vec<StageMetric>,
}

pub async fn run() -> Result<(), DynError> {
    let mut state = ExperimentState::new()?;

    let mut stage = state.start_stage(
        "bootstrap_runtime_cold_start",
        "experiment_harness",
        "bootstrap_runtime",
    );
    let _bootstrap_probe = serde_json::to_vec(&json!({
        "bootstrap": true,
        "profile": qemu_profile().intended_target,
    }))?;
    state.finish_stage(stage, 0);

    stage = state.start_stage(
        "initialize_spacex_operator_keys",
        "spacex_operator",
        "initialize_device_keys",
    );
    let spacex = SubjectKeys::new_bbs()?;
    state.finish_stage(stage, 0);

    stage = state.start_stage(
        "initialize_vantor_operator_keys",
        "vantor_operator",
        "initialize_device_keys",
    );
    let vantor = SubjectKeys::new_bbs()?;
    state.finish_stage(stage, 0);

    stage = state.start_stage(
        "initialize_user_device_keys",
        "user_terminal",
        "initialize_device_keys",
    );
    let user_issuer = SubjectKeys::new_bbs()?;
    let user = SubjectKeys::new_ed25519()?;
    state.finish_stage(stage, 0);

    stage = state.start_stage(
        "initialize_spacex_leo_keys",
        "spacex_leo",
        "initialize_device_keys",
    );
    let spacex_leo = SubjectKeys::new_ed25519()?;
    state.finish_stage(stage, 0);

    stage = state.start_stage(
        "initialize_vantor_leo_keys",
        "vantor_leo",
        "initialize_device_keys",
    );
    let vantor_leo = SubjectKeys::new_ed25519()?;
    state.finish_stage(stage, 0);

    stage = state.start_stage("load_did_cache", "experiment_harness", "load_did_cache");
    let spacex_did: DIDBuf = "did:web:spacex.com".parse()?;
    let vantor_did: DIDBuf = "did:web:vantor.com".parse()?;

    let spacex_doc = did_web_document(spacex_did.as_did(), public_key_multibase(&spacex.did)?);
    let vantor_doc = did_web_document(vantor_did.as_did(), public_key_multibase(&vantor.did)?);

    write_json(
        &state.did_cache_dir.join("did-web-spacex.com.json"),
        &spacex_doc,
    )?;
    write_json(
        &state.did_cache_dir.join("did-web-vantor.com.json"),
        &vantor_doc,
    )?;

    let resolver = OfflineDidResolver::new([
        (
            spacex_did.to_string(),
            serde_json::to_vec_pretty(&spacex_doc)?,
        ),
        (
            vantor_did.to_string(),
            serde_json::to_vec_pretty(&vantor_doc)?,
        ),
    ]);
    let vm_resolver: VerificationMethodDIDResolver<_, AnyMethod> =
        VerificationMethodDIDResolver::new(resolver);
    let verification_params = VerificationParameters::from_resolver(&vm_resolver);
    state.finish_stage(stage, 0);

    // This is a harness calibration stage, not a protocol artifact. QEMU TCG,
    // JSON-LD expansion, allocator growth, and the BBS+ issuing path all have
    // first-use costs that would otherwise be hidden inside the first real VC.
    stage = state.start_stage(
        "warmup_bbs2023_issue_path",
        "experiment_harness",
        "warmup_bbs2023_issue",
    );
    let _warmup_vc = issue_roaming_contract(
        &vm_resolver,
        &spacex,
        spacex_did.as_did(),
        &user.did.to_string(),
        &user.did.to_string(),
        &spacex_did,
        &vantor_did,
        "000000000001",
    )
    .await?;
    state.finish_stage(stage, 0);

    // Stage 1: User and SpaceX sign a roaming contract.
    // Artifacts:
    // - 01-spacex-issued-user-roaming-contract-base-vc.json
    // - 02-user-issued-spacex-roaming-contract-base-vc.json
    stage = state.start_stage(
        "issue_spacex_to_user_roaming_contract",
        "spacex_operator",
        "issue_bbs2023_vc",
    );
    let spacex_issued_roaming_contract = issue_roaming_contract(
        &vm_resolver,
        &spacex,
        spacex_did.as_did(),
        &user.did.to_string(),
        &user.did.to_string(),
        &spacex_did,
        &vantor_did,
        "000000000301",
    )
    .await?;
    let spacex_issued_roaming_path = state
        .artifact_dir
        .join("01-spacex-issued-user-roaming-contract-base-vc.json");
    write_json(&spacex_issued_roaming_path, &spacex_issued_roaming_contract)?;
    state.finish_stage(stage, file_len(&spacex_issued_roaming_path)?);

    stage = state.start_stage(
        "issue_user_to_spacex_roaming_contract",
        "user_terminal",
        "issue_bbs2023_vc",
    );
    let user_issued_roaming_contract = issue_roaming_contract(
        &vm_resolver,
        &user_issuer,
        user_issuer.did.as_did(),
        &spacex_did.to_string(),
        &user.did.to_string(),
        &spacex_did,
        &vantor_did,
        "000000000302",
    )
    .await?;
    let user_issued_roaming_path = state
        .artifact_dir
        .join("02-user-issued-spacex-roaming-contract-base-vc.json");
    write_json(&user_issued_roaming_path, &user_issued_roaming_contract)?;
    state.finish_stage(stage, file_len(&user_issued_roaming_path)?);

    // Stage 2: SpaceX and Vantor sign their cooperation agreement.
    // Artifacts:
    // - 03-spacex-issued-vantor-cooperation-agreement-base-vc.json
    // - 04-vantor-issued-spacex-cooperation-agreement-base-vc.json
    stage = state.start_stage(
        "issue_spacex_to_vantor_cooperation",
        "spacex_operator",
        "issue_bbs2023_vc",
    );
    let spacex_issued_cooperation = issue_cooperation_agreement(
        &vm_resolver,
        &spacex,
        spacex_did.as_did(),
        &spacex_did,
        &vantor_did,
        "000000000101",
    )
    .await?;
    let spacex_issued_cooperation_path = state
        .artifact_dir
        .join("03-spacex-issued-vantor-cooperation-agreement-base-vc.json");
    write_json(&spacex_issued_cooperation_path, &spacex_issued_cooperation)?;
    state.finish_stage(stage, file_len(&spacex_issued_cooperation_path)?);

    stage = state.start_stage(
        "issue_vantor_to_spacex_cooperation",
        "vantor_operator",
        "issue_bbs2023_vc",
    );
    let vantor_issued_cooperation = issue_cooperation_agreement(
        &vm_resolver,
        &vantor,
        vantor_did.as_did(),
        &vantor_did,
        &spacex_did,
        "000000000102",
    )
    .await?;
    let vantor_issued_cooperation_path = state
        .artifact_dir
        .join("04-vantor-issued-spacex-cooperation-agreement-base-vc.json");
    write_json(&vantor_issued_cooperation_path, &vantor_issued_cooperation)?;
    state.finish_stage(stage, file_len(&vantor_issued_cooperation_path)?);

    // Stage 3: SpaceX and Vantor assign authorization VCs to their LEOs.
    // The LeoAuth subject includes the cooperation agreement id so each LEO can
    // later disclose that it operates under the SpaceX/Vantor agreement.
    // Artifacts:
    // - 05-spacex-leo-auth-base-vc.json
    // - 06-vantor-leo-auth-base-vc.json
    stage = state.start_stage(
        "assign_spacex_leo_authorization",
        "spacex_operator",
        "issue_bbs2023_vc",
    );
    let spacex_leo_auth = issue_leo_authorization(
        &vm_resolver,
        &spacex,
        &spacex_did,
        &spacex_leo,
        "spacex-leo-0001",
        "1001",
    )
    .await?;
    let spacex_auth_path = state.artifact_dir.join("05-spacex-leo-auth-base-vc.json");
    write_json(&spacex_auth_path, &spacex_leo_auth)?;
    state.finish_stage(stage, file_len(&spacex_auth_path)?);

    stage = state.start_stage(
        "assign_vantor_leo_authorization",
        "vantor_operator",
        "issue_bbs2023_vc",
    );
    let vantor_leo_auth = issue_leo_authorization(
        &vm_resolver,
        &vantor,
        &vantor_did,
        &vantor_leo,
        "vantor-leo-0001",
        "2001",
    )
    .await?;
    let vantor_auth_path = state.artifact_dir.join("06-vantor-leo-auth-base-vc.json");
    write_json(&vantor_auth_path, &vantor_leo_auth)?;
    state.finish_stage(stage, file_len(&vantor_auth_path)?);

    // Stage 4: User and Starlink LEO mutually present VPs.
    // User presents one roaming contract as a BBS derived VC inside a signed
    // VP. Starlink LEO presents its SpaceX LeoAuth as a BBS derived VC inside
    // a signed VP. The VP signatures prove holder control; the embedded BBS
    // proofs prove issuer-signed claims with selective disclosure.
    // Artifacts:
    // - 07-spacex-issued-user-roaming-contract-derived-vc.json
    // - 09-user-to-spacex-leo-vp.json
    // - 10-spacex-leo-auth-derived-vc.json
    // - 11-spacex-leo-to-user-vp.json
    stage = state.start_stage(
        "build_user_to_spacex_leo_vp",
        "user_terminal",
        "derive_vc_and_sign_vp",
    );
    let (spacex_issued_derived_contract, user_to_spacex_leo_vp) = derive_user_contract_vp(
        &vm_resolver,
        &spacex_issued_roaming_contract,
        &verification_params,
        &user,
    )
    .await?;
    let spacex_issued_contract_derived_path = state
        .artifact_dir
        .join("07-spacex-issued-user-roaming-contract-derived-vc.json");
    let user_to_spacex_leo_vp_path = state.artifact_dir.join("09-user-to-spacex-leo-vp.json");
    write_json(
        &spacex_issued_contract_derived_path,
        &spacex_issued_derived_contract,
    )?;
    write_json(&user_to_spacex_leo_vp_path, &user_to_spacex_leo_vp)?;
    state.finish_stage(
        stage,
        file_len(&spacex_issued_contract_derived_path)? + file_len(&user_to_spacex_leo_vp_path)?,
    );

    stage = state.start_stage(
        "build_spacex_leo_to_user_vp",
        "spacex_leo",
        "derive_vc_and_sign_vp",
    );
    let (spacex_leo_derived_auth, spacex_leo_to_user_vp) = derive_leo_vp(
        &vm_resolver,
        &spacex_leo_auth,
        &verification_params,
        &spacex_leo,
        "000000000402",
    )
    .await?;
    let spacex_leo_user_derived_path = state
        .artifact_dir
        .join("10-spacex-leo-auth-derived-vc.json");
    let spacex_leo_to_user_vp_path = state.artifact_dir.join("11-spacex-leo-to-user-vp.json");
    write_json(&spacex_leo_user_derived_path, &spacex_leo_derived_auth)?;
    write_json(&spacex_leo_to_user_vp_path, &spacex_leo_to_user_vp)?;
    state.finish_stage(
        stage,
        file_len(&spacex_leo_user_derived_path)? + file_len(&spacex_leo_to_user_vp_path)?,
    );

    stage = state.start_stage(
        "verify_at_spacex_leo_user_vp",
        "spacex_leo",
        "verify_vp_and_embedded_vc",
    );
    let spacex_leo_verifies_user_roaming_vc_proof = spacex_issued_derived_contract
        .verify(&verification_params)
        .await?;
    let spacex_leo_verifies_user_vp = user_to_spacex_leo_vp.verify(&verification_params).await?;
    assert!(
        spacex_leo_verifies_user_roaming_vc_proof.is_ok() && spacex_leo_verifies_user_vp.is_ok(),
        "SpaceX LEO failed to verify User VP"
    );
    state.finish_stage(stage, 0);

    stage = state.start_stage(
        "verify_at_user_spacex_leo_vp",
        "user_terminal",
        "verify_vp_and_embedded_vc",
    );
    let user_verifies_spacex_leo_auth_vc_proof =
        spacex_leo_derived_auth.verify(&verification_params).await?;
    let user_verifies_spacex_leo_vp = spacex_leo_to_user_vp.verify(&verification_params).await?;
    assert!(
        user_verifies_spacex_leo_auth_vc_proof.is_ok() && user_verifies_spacex_leo_vp.is_ok(),
        "User failed to verify SpaceX LEO VP"
    );
    state.finish_stage(stage, 0);

    // Stage 5: Starlink LEO and Vantor LEO mutually present VPs.
    // Each LEO presents exactly one cooperation VC that was issued by the peer
    // operator. This proves the counterparty recognized the shared
    // coop-spacex-vantor-2026 agreement without packing extra local credentials
    // into the VP.
    stage = state.start_stage(
        "build_spacex_leo_to_vantor_leo_vp",
        "spacex_leo",
        "derive_vc_and_sign_vp",
    );
    let vantor_issued_cooperation_derived =
        derive_cooperation_vc(&vantor_issued_cooperation, &verification_params).await?;
    let spacex_leo_vp = sign_single_credential_vp(
        &vm_resolver,
        &spacex_leo,
        "000000000501",
        vantor_issued_cooperation_derived.clone(),
        "2026-06-01T00:00:04Z",
    )
    .await?;
    let vantor_issued_cooperation_derived_path = state
        .artifact_dir
        .join("12-vantor-issued-spacex-cooperation-derived-vc.json");
    let spacex_leo_vp_path = state
        .artifact_dir
        .join("13-spacex-leo-to-vantor-leo-vp.json");
    write_json(
        &vantor_issued_cooperation_derived_path,
        &vantor_issued_cooperation_derived,
    )?;
    write_json(&spacex_leo_vp_path, &spacex_leo_vp)?;
    state.finish_stage(
        stage,
        file_len(&vantor_issued_cooperation_derived_path)? + file_len(&spacex_leo_vp_path)?,
    );

    stage = state.start_stage(
        "build_vantor_leo_to_spacex_leo_vp",
        "vantor_leo",
        "derive_vc_and_sign_vp",
    );
    let spacex_issued_cooperation_derived =
        derive_cooperation_vc(&spacex_issued_cooperation, &verification_params).await?;
    let vantor_leo_vp = sign_single_credential_vp(
        &vm_resolver,
        &vantor_leo,
        "000000000502",
        spacex_issued_cooperation_derived.clone(),
        "2026-06-01T00:00:05Z",
    )
    .await?;
    let spacex_issued_cooperation_derived_path = state
        .artifact_dir
        .join("14-spacex-issued-vantor-cooperation-derived-vc.json");
    let vantor_leo_vp_path = state
        .artifact_dir
        .join("15-vantor-leo-to-spacex-leo-vp.json");
    write_json(
        &spacex_issued_cooperation_derived_path,
        &spacex_issued_cooperation_derived,
    )?;
    write_json(&vantor_leo_vp_path, &vantor_leo_vp)?;
    state.finish_stage(
        stage,
        file_len(&spacex_issued_cooperation_derived_path)? + file_len(&vantor_leo_vp_path)?,
    );

    stage = state.start_stage(
        "verify_at_spacex_leo_vantor_vp",
        "spacex_leo",
        "verify_vp_and_embedded_vc",
    );
    let spacex_leo_verifies_vantor_cooperation_vc_proof = spacex_issued_cooperation_derived
        .verify(&verification_params)
        .await?;
    let spacex_peer_vp_verify = vantor_leo_vp.verify(&verification_params).await?;
    assert!(
        spacex_leo_verifies_vantor_cooperation_vc_proof.is_ok() && spacex_peer_vp_verify.is_ok(),
        "SpaceX LEO failed to verify Vantor LEO VP"
    );
    state.finish_stage(stage, 0);

    stage = state.start_stage(
        "verify_at_vantor_leo_spacex_vp",
        "vantor_leo",
        "verify_vp_and_embedded_vc",
    );
    let vantor_leo_verifies_spacex_cooperation_vc_proof = vantor_issued_cooperation_derived
        .verify(&verification_params)
        .await?;
    let vantor_peer_vp_verify = spacex_leo_vp.verify(&verification_params).await?;
    assert!(
        vantor_leo_verifies_spacex_cooperation_vc_proof.is_ok() && vantor_peer_vp_verify.is_ok(),
        "Vantor LEO failed to verify SpaceX LEO VP"
    );
    state.finish_stage(stage, 0);

    stage = state.start_stage(
        "end_to_end_relay_authorization",
        "spacex_leo",
        "make_relay_decision",
    );
    let decision = json!({
        "decision": "allow",
        "reason": "BBS derived roaming contract verified offline; revocation checks intentionally skipped",
        "spacexLeo": spacex_leo.did,
        "vantorLeo": vantor_leo.did,
        "didWebCache": [
            "fixtures/did-cache/did-web-spacex.com.json",
            "fixtures/did-cache/did-web-vantor.com.json"
        ],
        "userStarlinkPresentations": [
            "09-user-to-spacex-leo-vp.json",
            "11-spacex-leo-to-user-vp.json"
        ],
        "mutualLeoPresentations": [
            "13-spacex-leo-to-vantor-leo-vp.json",
            "15-vantor-leo-to-spacex-leo-vp.json"
        ]
    });
    let decision_path = state.artifact_dir.join("17-relay-decision.json");
    write_json(&decision_path, &decision)?;
    state.finish_stage(stage, file_len(&decision_path)?);

    state.write_summary()?;
    println!("run_id = {}", state.run_id);
    println!("results = {}", state.result_dir.display());
    println!(
        "metrics = {}",
        state.result_dir.join("metrics.jsonl").display()
    );
    println!(
        "summary = {}",
        state.result_dir.join("summary.json").display()
    );

    Ok(())
}

async fn issue_cooperation_agreement(
    resolver: &VerificationMethodDIDResolver<OfflineDidResolver, AnyMethod>,
    issuer: &SubjectKeys,
    issuer_did: &ssi_dids_core::DID,
    partner_did: &DIDBuf,
    subject_did: &DIDBuf,
    uuid_suffix: &str,
) -> Result<AnyDataIntegrity<JsonCredential<CooperationAgreementSubject>>, DynError> {
    issue_bbs_vc(
        resolver,
        &issuer.jwk,
        issuer_did,
        &format!("urn:uuid:00000000-0000-0000-0000-{uuid_suffix}"),
        CooperationAgreementSubject {
            id: subject_did.to_string(),
            partner: partner_did.to_string(),
            agreement_id: "coop-spacex-vantor-2026".to_string(),
            scope: "Cross-constellation LEO relay and roaming".to_string(),
        },
        "2026-06-01T00:00:00Z",
    )
    .await
}

async fn issue_leo_authorization(
    resolver: &VerificationMethodDIDResolver<OfflineDidResolver, AnyMethod>,
    issuer: &SubjectKeys,
    issuer_did: &DIDBuf,
    leo: &SubjectKeys,
    satellite_id: &str,
    status_list_index: &str,
) -> Result<AnyDataIntegrity<JsonCredential<LeoAuthorizationSubject>>, DynError> {
    issue_bbs_vc(
        resolver,
        &issuer.jwk,
        issuer_did.as_did(),
        if satellite_id.starts_with("spacex") {
            "urn:uuid:00000000-0000-0000-0000-000000000201"
        } else {
            "urn:uuid:00000000-0000-0000-0000-000000000202"
        },
        LeoAuthorizationSubject {
            id: leo.did.to_string(),
            operator: issuer_did.to_string(),
            satellite_id: satellite_id.to_string(),
            status_list_index: status_list_index.to_string(),
            cooperation_agreement_id: "coop-spacex-vantor-2026".to_string(),
            maintenance_window: "2026-06-02T03:00:00Z/2026-06-02T04:00:00Z".to_string(),
        },
        "2026-06-01T00:00:00Z",
    )
    .await
}

async fn issue_roaming_contract(
    resolver: &VerificationMethodDIDResolver<OfflineDidResolver, AnyMethod>,
    issuer: &SubjectKeys,
    issuer_did: &ssi_dids_core::DID,
    subject_id: &str,
    requester: &str,
    spacex_did: &DIDBuf,
    vantor_did: &DIDBuf,
    uuid_suffix: &str,
) -> Result<AnyDataIntegrity<JsonCredential<RoamingContractSubject>>, DynError> {
    issue_bbs_vc(
        resolver,
        &issuer.jwk,
        issuer_did,
        &format!("urn:uuid:00000000-0000-0000-0000-{uuid_suffix}"),
        RoamingContractSubject {
            id: subject_id.to_string(),
            roaming_contract_id: "roaming-contract-0001".to_string(),
            requester: requester.to_string(),
            home_operator: spacex_did.to_string(),
            visited_operator: vantor_did.to_string(),
            authorized_for: "Vantor high-resolution imagery relay via SpaceX OISL".to_string(),
            billing_reference: "billing-private-2026-0001".to_string(),
            internal_policy: "internal-qos-tier-gold".to_string(),
        },
        "2026-06-01T00:00:00Z",
    )
    .await
}

async fn derive_user_contract_vp(
    resolver: &VerificationMethodDIDResolver<OfflineDidResolver, AnyMethod>,
    spacex_issued_contract: &AnyDataIntegrity<JsonCredential<RoamingContractSubject>>,
    verification_params: &VerificationParameters<
        &VerificationMethodDIDResolver<OfflineDidResolver, AnyMethod>,
    >,
    user: &SubjectKeys,
) -> Result<
    (
        AnyDataIntegrity,
        AnyDataIntegrity<JsonPresentation<AnyDataIntegrity>>,
    ),
    DynError,
> {
    let spacex_issued_derived: AnyDataIntegrity = serde_json::from_value(serde_json::to_value(
        &derive_roaming_contract(spacex_issued_contract, verification_params).await?,
    )?)?;
    let roaming_vp = sign_single_credential_vp(
        resolver,
        user,
        "000000000401",
        spacex_issued_derived.clone(),
        "2026-06-01T00:00:02Z",
    )
    .await?;

    Ok((spacex_issued_derived, roaming_vp))
}

async fn derive_cooperation_vc(
    cooperation: &AnyDataIntegrity<JsonCredential<CooperationAgreementSubject>>,
    verification_params: &VerificationParameters<
        &VerificationMethodDIDResolver<OfflineDidResolver, AnyMethod>,
    >,
) -> Result<AnyDataIntegrity, DynError> {
    let derived = derive_cooperation_agreement(cooperation, verification_params).await?;
    serde_json::from_value(serde_json::to_value(&derived)?).map_err(Into::into)
}

async fn derive_leo_vp(
    resolver: &VerificationMethodDIDResolver<OfflineDidResolver, AnyMethod>,
    leo_authorization: &AnyDataIntegrity<JsonCredential<LeoAuthorizationSubject>>,
    verification_params: &VerificationParameters<
        &VerificationMethodDIDResolver<OfflineDidResolver, AnyMethod>,
    >,
    leo: &SubjectKeys,
    uuid_suffix: &str,
) -> Result<
    (
        AnyDataIntegrity,
        AnyDataIntegrity<JsonPresentation<AnyDataIntegrity>>,
    ),
    DynError,
> {
    let derived_auth = derive_leo_authorization(leo_authorization, verification_params).await?;
    let verifiable_derived_auth: AnyDataIntegrity =
        serde_json::from_value(serde_json::to_value(&derived_auth)?)?;
    let vp = sign_single_credential_vp(
        resolver,
        leo,
        uuid_suffix,
        verifiable_derived_auth.clone(),
        "2026-06-01T00:00:03Z",
    )
    .await?;

    Ok((verifiable_derived_auth, vp))
}

async fn sign_single_credential_vp(
    resolver: &VerificationMethodDIDResolver<OfflineDidResolver, AnyMethod>,
    holder: &SubjectKeys,
    uuid_suffix: &str,
    credential: AnyDataIntegrity,
    proof_created: &str,
) -> Result<AnyDataIntegrity<JsonPresentation<AnyDataIntegrity>>, DynError> {
    let vp = JsonPresentation::new(
        Some(format!("urn:uuid:00000000-0000-0000-0000-{uuid_suffix}").parse()?),
        vec![holder.did.clone().into_uri().into()],
        vec![credential],
    );
    sign_holder_vp(
        resolver,
        &holder.jwk,
        holder.did.as_did(),
        vp,
        proof_created,
    )
    .await
}

impl ExperimentState {
    fn new() -> Result<Self, DynError> {
        let run_id = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs()
            .to_string();
        let result_dir = workspace_path(&[RESULTS_ROOT, &format!("run-{run_id}")]);
        let artifact_dir = result_dir.join("artifacts");
        let did_cache_dir = workspace_path(&[DID_CACHE_ROOT]);
        ensure_dir(&artifact_dir)?;
        ensure_dir(&did_cache_dir)?;
        Ok(Self {
            run_id,
            result_dir,
            artifact_dir,
            did_cache_dir,
            metrics: Vec::new(),
            seen_actors: HashSet::new(),
            process_cold_start_recorded: false,
        })
    }

    fn start_stage(
        &mut self,
        stage: &'static str,
        actor: &'static str,
        operation: &'static str,
    ) -> StageTimer {
        let includes_process_cold_start = !self.process_cold_start_recorded;
        self.process_cold_start_recorded = true;

        let includes_actor_cold_start = self.seen_actors.insert(actor);
        StageTimer::start_for(
            stage,
            actor,
            operation,
            includes_process_cold_start,
            includes_actor_cold_start,
        )
    }

    fn finish_stage(&mut self, timer: StageTimer, artifact_bytes: u64) {
        let metric = timer.finish(artifact_bytes);
        println!("{:<32} {:>10.3} ms", metric.stage, metric.wall_time_ms);
        self.metrics.push(metric);
    }

    fn write_summary(&self) -> Result<(), DynError> {
        let metrics_path = self.result_dir.join("metrics.jsonl");
        let mut metrics_jsonl = String::new();
        for metric in &self.metrics {
            metrics_jsonl.push_str(&serde_json::to_string(metric)?);
            metrics_jsonl.push('\n');
        }
        write_text(&metrics_path, &metrics_jsonl)?;

        let summary = ExperimentSummary {
            run_id: self.run_id.clone(),
            qemu_profile: qemu_profile(),
            metrics: self.metrics.clone(),
        };
        write_json(&self.result_dir.join("summary.json"), &summary)
    }
}
