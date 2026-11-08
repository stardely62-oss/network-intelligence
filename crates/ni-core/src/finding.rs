//! Diagnostic findings.
//!
//! A finding separates *what was observed* (with its own observation
//! confidence) from *what might explain it* (hypotheses, each with a
//! confidence, plus alternative explanations). No rule may state that DPI
//! or any other cause is proven.

use serde::{Deserialize, Serialize};

pub const FINDING_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Category {
    /// Gaps in what could be observed.
    Observability,
    TcpHandshake,
    TcpReset,
    TlsHandshake,
    Dns,
    Udp,
    /// Difference between the application and a control/probe connection.
    ControlComparison,
    IpFiltering,
    SniFiltering,
    Throttling,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Severity {
    Info,
    Notice,
    Warning,
    Problem,
}

/// Confidence on a fixed, coarse scale. Numbers would suggest a precision
/// the evidence does not have.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Confidence {
    VeryLow,
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Observation {
    pub text: String,
    /// How reliable the observation itself is.
    pub confidence: Confidence,
    pub source: crate::source::DataSource,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum Evidence {
    Endpoint { endpoint_id: u64 },
    Probe { probe_id: String },
    Event { ts: i64, kind: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Hypothesis {
    pub text: String,
    /// Confidence that this hypothesis explains the observations.
    pub confidence: Confidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    /// Deterministic id: `<rule id>:<subject>`.
    pub id: String,
    pub rule: String,
    pub category: Category,
    pub severity: Severity,
    pub title: String,
    pub observations: Vec<Observation>,
    pub evidence: Vec<Evidence>,
    pub hypotheses: Vec<Hypothesis>,
    pub alternative_explanations: Vec<String>,
    /// Overall confidence that the hypotheses identify the cause. Never
    /// higher than `Medium` for snapshot-only evidence.
    pub confidence: Confidence,
    pub limitations: Vec<String>,
    pub suggested_checks: Vec<String>,
}
