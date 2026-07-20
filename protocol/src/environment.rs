//! Bounded environment-minimization proof shared across execution surfaces.

use crate::{ProtocolError, ReasonCode};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const ENVIRONMENT_ENVELOPE_VERSION: u16 = 1;
pub const MAX_ENVIRONMENT_TRIALS: usize = 4_096;
const MAX_ENVIRONMENT_TEXT_BYTES: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum EnvironmentOutcome {
    Reproduces,
    DoesNotReproduce,
    Abstain,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EnvironmentTrial {
    pub dimension: String,
    pub baseline: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub candidate: Option<String>,
    pub outcome: EnvironmentOutcome,
    pub reason: String,
    pub replay_attempts: u16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EnvironmentEnvelope {
    pub version: u16,
    pub complete: bool,
    pub replay_attempts: u16,
    #[serde(default)]
    pub relaxed_dimensions: BTreeSet<String>,
    #[serde(default)]
    pub trials: Vec<EnvironmentTrial>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EnvironmentProof {
    pub captured: BTreeMap<String, String>,
    pub envelope: EnvironmentEnvelope,
}

impl EnvironmentProof {
    pub fn validate(&self) -> Result<(), ProtocolError> {
        self.envelope.validate(&self.captured)
    }
}

impl Default for EnvironmentEnvelope {
    fn default() -> Self {
        Self {
            version: ENVIRONMENT_ENVELOPE_VERSION,
            complete: false,
            replay_attempts: 0,
            relaxed_dimensions: BTreeSet::new(),
            trials: Vec::new(),
        }
    }
}

impl EnvironmentEnvelope {
    pub fn validate(&self, captured: &BTreeMap<String, String>) -> Result<(), ProtocolError> {
        if self.version != ENVIRONMENT_ENVELOPE_VERSION {
            return Err(ProtocolError::new(ReasonCode::UnsupportedVersion));
        }
        if self.trials.len() > MAX_ENVIRONMENT_TRIALS {
            return Err(ProtocolError::new(ReasonCode::BatchTooLarge));
        }
        if !self.complete && !self.relaxed_dimensions.is_empty() {
            return Err(ProtocolError::new(ReasonCode::InvalidEvent));
        }
        let mut dimensions = BTreeSet::new();
        let mut recorded_attempts = 0u32;
        for trial in &self.trials {
            if !captured.contains_key(&trial.dimension)
                || !dimensions.insert(trial.dimension.clone())
                || trial.dimension.len() > MAX_ENVIRONMENT_TEXT_BYTES
                || trial.baseline.len() > MAX_ENVIRONMENT_TEXT_BYTES
                || trial
                    .candidate
                    .as_ref()
                    .is_some_and(|value| value.len() > MAX_ENVIRONMENT_TEXT_BYTES)
                || trial.reason.len() > MAX_ENVIRONMENT_TEXT_BYTES
                || captured.get(&trial.dimension) != Some(&trial.baseline)
            {
                return Err(ProtocolError::new(ReasonCode::InvalidEvent));
            }
            match trial.outcome {
                EnvironmentOutcome::Reproduces if trial.replay_attempts == 0 => {
                    return Err(ProtocolError::new(ReasonCode::InvalidSequence));
                }
                EnvironmentOutcome::DoesNotReproduce if trial.replay_attempts < 2 => {
                    return Err(ProtocolError::new(ReasonCode::InvalidSequence));
                }
                _ => {}
            }
            recorded_attempts += u32::from(trial.replay_attempts);
        }
        let attempts = u32::from(self.replay_attempts);
        let valid_attempts = if self.complete {
            attempts == recorded_attempts.saturating_add(1)
        } else {
            attempts == recorded_attempts || attempts == recorded_attempts.saturating_add(1)
        };
        if !valid_attempts {
            return Err(ProtocolError::new(ReasonCode::InvalidSequence));
        }
        for dimension in &self.relaxed_dimensions {
            let valid = self.trials.iter().any(|trial| {
                &trial.dimension == dimension && trial.outcome == EnvironmentOutcome::Reproduces
            });
            if !valid {
                return Err(ProtocolError::new(ReasonCode::InvalidEvent));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relaxed_dimension_requires_a_complete_reproducing_trial() {
        let captured = BTreeMap::from([("define:MODE".into(), "debug".into())]);
        let mut envelope = EnvironmentEnvelope {
            complete: true,
            replay_attempts: 2,
            relaxed_dimensions: BTreeSet::from(["define:MODE".into()]),
            trials: vec![EnvironmentTrial {
                dimension: "define:MODE".into(),
                baseline: "debug".into(),
                candidate: None,
                outcome: EnvironmentOutcome::Abstain,
                reason: "candidate-replay-incomplete".into(),
                replay_attempts: 1,
            }],
            ..EnvironmentEnvelope::default()
        };
        assert_eq!(
            envelope.validate(&captured).unwrap_err().reason,
            ReasonCode::InvalidEvent
        );

        envelope.trials[0].outcome = EnvironmentOutcome::Reproduces;
        envelope.trials[0].replay_attempts = 1;
        assert!(envelope.validate(&captured).is_ok());
        envelope.complete = false;
        assert_eq!(
            envelope.validate(&captured).unwrap_err().reason,
            ReasonCode::InvalidEvent
        );
    }
}
