use did_method_key::DIDKey;
use serde::{Deserialize, Serialize};
use ssi_dids_core::DIDBuf;
use ssi_jwk::JWK;

use crate::error::DynError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CooperationAgreementSubject {
    #[serde(rename = "id")]
    pub id: String,

    #[serde(rename = "https://example.org/leo#partner")]
    pub partner: String,

    #[serde(rename = "https://example.org/leo#agreementId")]
    pub agreement_id: String,

    #[serde(rename = "https://example.org/leo#scope")]
    pub scope: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeoAuthorizationSubject {
    #[serde(rename = "id")]
    pub id: String,

    #[serde(rename = "https://example.org/leo#operator")]
    pub operator: String,

    #[serde(rename = "https://example.org/leo#satelliteId")]
    pub satellite_id: String,

    // The PDF includes statusListIndex in the authorization flow. We keep it as
    // ordinary experimental data, but deliberately do not emit credentialStatus
    // because this experiment excludes Bitstring Status List checks.
    #[serde(rename = "https://example.org/leo#statusListIndex")]
    pub status_list_index: String,

    #[serde(rename = "https://example.org/leo#cooperationAgreementId")]
    pub cooperation_agreement_id: String,

    #[serde(rename = "https://example.org/leo#maintenanceWindow")]
    pub maintenance_window: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoamingContractSubject {
    #[serde(rename = "id")]
    pub id: String,

    #[serde(rename = "https://example.org/leo#roamingContractId")]
    pub roaming_contract_id: String,

    #[serde(rename = "https://example.org/leo#requester")]
    pub requester: String,

    #[serde(rename = "https://example.org/leo#homeOperator")]
    pub home_operator: String,

    #[serde(rename = "https://example.org/leo#visitedOperator")]
    pub visited_operator: String,

    #[serde(rename = "https://example.org/leo#authorizedFor")]
    pub authorized_for: String,

    #[serde(rename = "https://example.org/leo#billingReference")]
    pub billing_reference: String,

    #[serde(rename = "https://example.org/leo#internalPolicy")]
    pub internal_policy: String,
}

#[derive(Debug, Clone)]
pub struct SubjectKeys {
    pub jwk: JWK,
    pub did: DIDBuf,
}

impl SubjectKeys {
    pub fn new_bbs() -> Result<Self, DynError> {
        let jwk = JWK::generate_bls12381g2();
        let did = DIDKey::generate(&jwk)?;
        Ok(Self { jwk, did })
    }

    pub fn new_ed25519() -> Result<Self, DynError> {
        let jwk = JWK::generate_ed25519()?;
        let did = DIDKey::generate(&jwk)?;
        Ok(Self { jwk, did })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct QemuProfile {
    pub intended_target: &'static str,
    pub config_path: &'static str,
    pub qemu_binary: &'static str,
    pub machine: &'static str,
    pub cpu: &'static str,
    pub smp: u8,
    pub memory: &'static str,
    pub recommended_command: &'static str,
    pub approximates: &'static [&'static str],
    pub not_emulated: &'static [&'static str],
    pub power_model: &'static str,
    pub notes: &'static [&'static str],
}

pub fn qemu_profile() -> QemuProfile {
    QemuProfile {
        intended_target: "NOVI LLC USA Gen 2 OBC AMD/Xilinx Versal AI Edge Series",
        config_path: "configs/qemu/novi-gen2-obc.json",
        qemu_binary: "qemu-system-aarch64",
        machine: "virt",
        cpu: "cortex-a72",
        smp: 2,
        memory: "1024M",
        recommended_command: "scripts/run-qemu-novi-gen2-obc.ps1",
        approximates: &[
            "Dual-core ARM Cortex-A72 Linux userspace path",
            "NOVI Gen 2 OBC application processor workload envelope",
            "Offline onboard verification of BBS+ VC/VP artifacts using cached did:web documents",
        ],
        not_emulated: &[
            "Dual-core ARM Cortex-R5F real-time subsystem",
            "Programmable Logic FPGA fabric",
            "AI Engines",
            "Vorago ARM Cortex-M4 MCU",
            "Embedded radiation-hardened FRAM behavior",
            "SEL immunity",
            "SEU/SEFI mitigation",
            "ECC protected memory interfaces",
            "Redundant boot image storage",
            "Actual platform power draw",
        ],
        power_model: "<0.75W low-power and 5-50W high-performance values are platform assumptions; QEMU does not measure OBC wattage.",
        notes: &[
            "QEMU cortex-a72 approximates only the dual-core A72 application processor path.",
            "Run inside an AArch64 Linux guest to collect Linux getrusage and /proc RSS metrics.",
            "Bitstring Status List revocation checks are intentionally omitted for this experiment.",
        ],
    }
}
