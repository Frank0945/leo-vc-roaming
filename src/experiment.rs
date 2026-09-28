use std::time::{Instant, SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::{
    bbs_binding::{
        Holder, Issuer, SubjectAttribute, VerifierRequest, blind_issue, present, verify,
    },
    error::DynError,
    fs_util::{ensure_dir, workspace_path, write_json},
    model::{CredentialKind, LEO_PARTNER, PARTNER_NCC, UE},
};

const RESULTS_ROOT: &str = "results";
const MEASURED_RUNS: usize = 50;
const FIGURE_5_ATTRIBUTE_COUNTS: [usize; 6] = [5, 6, 7, 8, 9, 10];
const FIGURE_5_REVEAL_RATIO: f64 = 0.8;
const FIGURE_6_ATTRIBUTE_COUNT: usize = 7;
const FIGURE_6_REVEAL_RATIOS: [f64; 5] = [0.2, 0.4, 0.6, 0.8, 1.0];
const FIGURE_7_ATTRIBUTE_COUNTS: [usize; 6] = [5, 6, 7, 8, 9, 10];
const FIGURE_7_REVEAL_RATIO: f64 = 0.4;
const WARM_UP_STAGE: &str = "Cryptographic initialization (warm-up)";
const GENERATE_STAGE: &str = "Partner LEO Gen. VP for UE";
const VERIFY_STAGE: &str = "Partner LEO Verify UE VP";

#[derive(Debug, Clone)]
struct Condition {
    figure: &'static str,
    attribute_count: usize,
    target_reveal_ratio: f64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct RawSample {
    figure: String,
    attribute_count: usize,
    target_reveal_ratio: f64,
    revealed_attribute_count: usize,
    effective_reveal_ratio: f64,
    iteration: usize,
    stage: String,
    wall_time_ms: f64,
    vp_payload_bytes: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Aggregate {
    figure: String,
    attribute_count: usize,
    target_reveal_ratio: f64,
    revealed_attribute_count: usize,
    effective_reveal_ratio: f64,
    measured_runs: usize,
    mean_time_ms: f64,
    p50_time_ms: f64,
    p95_time_ms: f64,
    mean_vp_payload_bytes: Option<f64>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct StageSummary {
    stage: &'static str,
    results: Vec<Aggregate>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct Summary {
    run_id: String,
    protocol: &'static str,
    benchmark_reference: &'static str,
    measured_runs_per_condition: usize,
    stages: Vec<StageSummary>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ExcelInput<'a> {
    run_id: &'a str,
    figure5: Vec<Aggregate>,
    figure6: Vec<Aggregate>,
    figure7: Vec<Aggregate>,
    raw_samples: &'a [RawSample],
    summary: &'a Summary,
}

pub async fn run() -> Result<(), DynError> {
    let run_id = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_secs()
        .to_string();
    let result_dir = workspace_path(&[RESULTS_ROOT, &format!("run-{run_id}")]);
    ensure_dir(&result_dir)?;
    let conditions = benchmark_conditions();
    let mut raw_samples = Vec::new();

    for condition in &conditions {
        run_condition(condition, &mut raw_samples)?;
    }

    let warmups = aggregate_stage(&raw_samples, WARM_UP_STAGE);
    let generations = aggregate_stage(&raw_samples, GENERATE_STAGE);
    let verifications = aggregate_stage(&raw_samples, VERIFY_STAGE);
    let figure5 = figure_slice(&verifications, "Figure 5");
    let figure6 = figure_slice(&generations, "Figure 6");
    let figure7 = figure_slice(&generations, "Figure 7");
    let summary = Summary {
        run_id: run_id.clone(),
        protocol: "BBS+ blind issuance with anonymous holder binding",
        benchmark_reference: "BBS_SAC2026 Figure 6 and Figure 7 parameter slices",
        measured_runs_per_condition: MEASURED_RUNS,
        stages: vec![
            StageSummary {
                stage: WARM_UP_STAGE,
                results: warmups,
            },
            StageSummary {
                stage: GENERATE_STAGE,
                results: generations,
            },
            StageSummary {
                stage: VERIFY_STAGE,
                results: verifications,
            },
        ],
    };
    write_json(&result_dir.join("summary.json"), &summary)?;
    write_json(&result_dir.join("figure5-data.json"), &figure5)?;
    write_json(&result_dir.join("figure6-data.json"), &figure6)?;
    write_json(&result_dir.join("figure7-data.json"), &figure7)?;
    write_json(&result_dir.join("timing-raw.json"), &raw_samples)?;
    write_json(
        &result_dir.join("excel-input.json"),
        &ExcelInput {
            run_id: &run_id,
            figure5,
            figure6,
            figure7,
            raw_samples: &raw_samples,
            summary: &summary,
        },
    )?;
    println!("run_id = {run_id}");
    println!("results = {}", result_dir.display());
    Ok(())
}

fn benchmark_conditions() -> Vec<Condition> {
    let mut conditions = FIGURE_5_ATTRIBUTE_COUNTS
        .into_iter()
        .map(|count| Condition {
            figure: "Figure 5",
            attribute_count: count,
            target_reveal_ratio: FIGURE_5_REVEAL_RATIO,
        })
        .collect::<Vec<_>>();
    conditions.extend(
        FIGURE_6_REVEAL_RATIOS
            .into_iter()
            .map(|ratio| Condition {
                figure: "Figure 6",
                attribute_count: FIGURE_6_ATTRIBUTE_COUNT,
                target_reveal_ratio: ratio,
            })
            .collect::<Vec<_>>(),
    );
    conditions.extend(
        FIGURE_7_ATTRIBUTE_COUNTS
            .into_iter()
            .map(|count| Condition {
                figure: "Figure 7",
                attribute_count: count,
                target_reveal_ratio: FIGURE_7_REVEAL_RATIO,
            }),
    );
    conditions
}

fn run_condition(condition: &Condition, samples: &mut Vec<RawSample>) -> Result<(), DynError> {
    let attributes = benchmark_attributes(condition.attribute_count);
    let reveal_indices =
        disclosure_indices(condition.attribute_count, condition.target_reveal_ratio);
    let revealed_count = reveal_indices.len();
    let effective_ratio = revealed_count as f64 / condition.attribute_count as f64;

    let started = Instant::now();
    let issuer = Issuer::generate_for_attributes(
        PARTNER_NCC,
        "did:web:partner-ncc.com",
        condition.attribute_count,
    );
    let ue = Holder::generate(UE);
    let credential = blind_issue(&issuer, &ue, CredentialKind::PartnerAccess, &attributes)?;
    let warmup_request = VerifierRequest::generate(LEO_PARTNER, CredentialKind::PartnerAccess);
    let warmup_presentation = present(&credential, &ue, &warmup_request, &reveal_indices)?;
    verify(&warmup_presentation, &warmup_request, &issuer)?;
    samples.push(sample(
        condition,
        revealed_count,
        effective_ratio,
        0,
        WARM_UP_STAGE,
        started.elapsed().as_secs_f64() * 1000.0,
        None,
    ));

    for iteration in 1..=MEASURED_RUNS {
        let request = VerifierRequest::generate(LEO_PARTNER, CredentialKind::PartnerAccess);
        let generation_started = Instant::now();
        let presentation = present(&credential, &ue, &request, &reveal_indices)?;
        let generation_ms = generation_started.elapsed().as_secs_f64() * 1000.0;
        let vp_payload_bytes = serde_json::to_vec(&presentation)?.len() as u64;
        samples.push(sample(
            condition,
            revealed_count,
            effective_ratio,
            iteration,
            GENERATE_STAGE,
            generation_ms,
            Some(vp_payload_bytes),
        ));

        let verification_started = Instant::now();
        verify(&presentation, &request, &issuer)?;
        samples.push(sample(
            condition,
            revealed_count,
            effective_ratio,
            iteration,
            VERIFY_STAGE,
            verification_started.elapsed().as_secs_f64() * 1000.0,
            Some(vp_payload_bytes),
        ));
    }
    Ok(())
}

fn benchmark_attributes(count: usize) -> Vec<SubjectAttribute> {
    (1..=count)
        .map(|index| SubjectAttribute {
            name: format!("attr_{index:02}"),
            // Attribute names are schema-defined and are not repeated in a VP.
            // Fixed eight-character values prevent value length from dominating the
            // Figure 6/7 payload comparison.
            value: format!("v{index:07}"),
        })
        .collect()
}

fn disclosure_indices(attribute_count: usize, target_ratio: f64) -> Vec<usize> {
    let reveal_count =
        ((attribute_count as f64 * target_ratio).round() as usize).min(attribute_count);
    (0..reveal_count).collect()
}

fn sample(
    condition: &Condition,
    revealed_count: usize,
    effective_ratio: f64,
    iteration: usize,
    stage: &str,
    wall_time_ms: f64,
    vp_payload_bytes: Option<u64>,
) -> RawSample {
    RawSample {
        figure: condition.figure.to_string(),
        attribute_count: condition.attribute_count,
        target_reveal_ratio: condition.target_reveal_ratio,
        revealed_attribute_count: revealed_count,
        effective_reveal_ratio: effective_ratio,
        iteration,
        stage: stage.to_string(),
        wall_time_ms,
        vp_payload_bytes,
    }
}

fn aggregate_stage(samples: &[RawSample], stage: &str) -> Vec<Aggregate> {
    benchmark_conditions()
        .into_iter()
        .map(|condition| {
            let group = samples
                .iter()
                .filter(|sample| {
                    sample.stage == stage
                        && sample.figure == condition.figure
                        && sample.attribute_count == condition.attribute_count
                        && sample.target_reveal_ratio == condition.target_reveal_ratio
                })
                .collect::<Vec<_>>();
            let mut timings = group
                .iter()
                .map(|sample| sample.wall_time_ms)
                .collect::<Vec<_>>();
            timings.sort_by(f64::total_cmp);
            let payloads = group
                .iter()
                .filter_map(|sample| sample.vp_payload_bytes)
                .map(|bytes| bytes as f64)
                .collect::<Vec<_>>();
            Aggregate {
                figure: condition.figure.to_string(),
                attribute_count: condition.attribute_count,
                target_reveal_ratio: condition.target_reveal_ratio,
                revealed_attribute_count: group[0].revealed_attribute_count,
                effective_reveal_ratio: group[0].effective_reveal_ratio,
                measured_runs: group.len(),
                mean_time_ms: mean(&timings),
                p50_time_ms: percentile(&timings, 0.50),
                p95_time_ms: percentile(&timings, 0.95),
                mean_vp_payload_bytes: (!payloads.is_empty()).then(|| mean(&payloads)),
            }
        })
        .collect()
}

fn figure_slice(values: &[Aggregate], figure: &str) -> Vec<Aggregate> {
    values
        .iter()
        .filter(|value| value.figure == figure)
        .cloned()
        .collect()
}
fn mean(values: &[f64]) -> f64 {
    values.iter().sum::<f64>() / values.len() as f64
}
fn percentile(values: &[f64], ratio: f64) -> f64 {
    values[((values.len() - 1) as f64 * ratio).round() as usize]
}
