//! Opt-in aggregate inference limits for a private engine process.
//! Admissions are conservative: failed requests are never refunded.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

pub const CALL_LIMIT: &str = "execution budget: model dispatch limit exhausted";
pub const WALL_LIMIT: &str = "execution budget: wall deadline exhausted";

#[derive(Debug)]
pub struct ExecutionBudget {
    max_calls: Option<u64>,
    deadline: Option<Instant>,
    calls: AtomicU64,
}

impl ExecutionBudget {
    fn new(max_calls: Option<u64>, wall_secs: Option<u64>) -> Result<Self, &'static str> {
        if max_calls == Some(0) || wall_secs == Some(0) {
            return Err("execution budget limits must be positive");
        }
        let deadline = wall_secs
            .map(|secs| {
                Instant::now()
                    .checked_add(Duration::from_secs(secs))
                    .ok_or("execution budget wall limit is too large")
            })
            .transpose()?;
        Ok(Self {
            max_calls,
            deadline,
            calls: AtomicU64::new(0),
        })
    }

    pub fn expired(&self) -> bool {
        self.deadline
            .is_some_and(|deadline| Instant::now() >= deadline)
    }

    pub fn remaining(&self) -> Option<Duration> {
        self.deadline
            .map(|deadline| deadline.saturating_duration_since(Instant::now()))
    }

    /// Advisory only; admission remains atomic and cannot exceed the cap.
    pub fn remaining_calls(&self) -> Option<u64> {
        self.max_calls
            .map(|max| max.saturating_sub(self.calls.load(Ordering::Acquire)))
    }

    pub fn admit(&self) -> Result<(), &'static str> {
        if self.expired() {
            return Err(WALL_LIMIT);
        }
        self.calls
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |calls| {
                if self.max_calls.is_some_and(|max| calls >= max) {
                    None
                } else {
                    calls.checked_add(1)
                }
            })
            .map(|_| ())
            .map_err(|_| CALL_LIMIT)
    }
}

fn parse_limit(value: Option<String>) -> Result<Option<u64>, &'static str> {
    value
        .map(|value| {
            value
                .trim()
                .parse::<u64>()
                .ok()
                .filter(|v| *v > 0)
                .ok_or("execution budget limits must be positive integers")
        })
        .transpose()
}

static PROCESS_BUDGET: OnceLock<Result<Option<Arc<ExecutionBudget>>, &'static str>> =
    OnceLock::new();

fn env_limit(name: &str) -> Result<Option<u64>, &'static str> {
    match std::env::var(name) {
        Ok(value) => parse_limit(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => {
            Err("execution budget limits must be UTF-8 integers")
        }
    }
}

pub fn process_budget() -> Result<Option<Arc<ExecutionBudget>>, &'static str> {
    PROCESS_BUDGET
        .get_or_init(|| {
            let calls = env_limit("FUIGO_MAX_MODEL_CALLS")?;
            let wall = env_limit("FUIGO_MAX_RUNTIME_SECS")?;
            if calls.is_none() && wall.is_none() {
                return Ok(None);
            }
            ExecutionBudget::new(calls, wall).map(|budget| Some(Arc::new(budget)))
        })
        .clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregate_admissions_do_not_overshoot_under_concurrency() {
        let budget = Arc::new(ExecutionBudget::new(Some(7), None).unwrap());
        let threads: Vec<_> = (0..32)
            .map(|_| {
                let budget = budget.clone();
                std::thread::spawn(move || budget.admit().is_ok())
            })
            .collect();
        assert_eq!(
            threads
                .into_iter()
                .map(|thread| usize::from(thread.join().unwrap()))
                .sum::<usize>(),
            7
        );
        assert_eq!(budget.calls.load(Ordering::Acquire), 7);
        assert_eq!(budget.admit(), Err(CALL_LIMIT));
    }

    #[test]
    fn expired_budget_rejects_without_spending_an_admission() {
        let budget = ExecutionBudget {
            max_calls: Some(3),
            deadline: Some(Instant::now()),
            calls: AtomicU64::new(0),
        };
        assert_eq!(budget.admit(), Err(WALL_LIMIT));
        assert_eq!(budget.calls.load(Ordering::Acquire), 0);
    }

    #[test]
    fn malformed_and_zero_limits_fail_closed() {
        for value in ["0", "-1", "", "not-a-number"] {
            assert!(parse_limit(Some(value.into())).is_err());
        }
        assert_eq!(parse_limit(Some(" 12 ".into())), Ok(Some(12)));
        assert_eq!(parse_limit(None), Ok(None));
    }
}
