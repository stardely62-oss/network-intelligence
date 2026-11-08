//! Rule-based diagnostics.
//!
//! Rules read the evidence of one session (endpoints, probes, coverage) and
//! produce [`Finding`]s. Each finding keeps observations (facts with their
//! own reliability) apart from hypotheses (possible causes with a
//! confidence), and always lists alternative explanations and limitations.
//!
//! Policy enforced by tests:
//! * snapshot- or probe-only evidence never yields a confidence above
//!   `Medium`;
//! * a hypothesis mentioning filtering/DPI never exceeds `Low`;
//! * TCP refusals and UDP silence are never presented as filtering.

mod rules;

use ni_core::endpoint::EndpointRecord;
use ni_core::finding::{Category, Finding};
use ni_core::probe::ProbeRecord;
use ni_core::source::Coverage;
use serde::Serialize;

pub struct SessionEvidence<'a> {
    pub endpoints: &'a [EndpointRecord],
    pub probes: &'a [ProbeRecord],
    pub coverage: &'a Coverage,
    pub duration_ms: i64,
}

pub trait Rule: Send + Sync {
    fn info(&self) -> RuleInfo;
    fn evaluate(&self, ev: &SessionEvidence<'_>) -> Vec<Finding>;
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleInfo {
    pub id: &'static str,
    pub category: Category,
    pub title: &'static str,
    pub status: RuleStatus,
    /// Data sources the rule needs.
    pub requires: &'static [&'static str],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum RuleStatus {
    Implemented,
    /// Designed, but the data it needs is not collected yet. Planned rules
    /// never produce findings.
    Planned,
}

pub fn rules() -> Vec<Box<dyn Rule>> {
    rules::implemented()
}

/// All rules including planned ones, for display.
pub fn catalog() -> Vec<RuleInfo> {
    let mut v: Vec<RuleInfo> = rules().iter().map(|r| r.info()).collect();
    v.extend(rules::planned());
    v
}

pub fn evaluate(ev: &SessionEvidence<'_>) -> Vec<Finding> {
    let mut out: Vec<Finding> = rules().iter().flat_map(|r| r.evaluate(ev)).collect();
    out.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.id.cmp(&b.id)));
    out
}
