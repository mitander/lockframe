//! Invariant checking for deterministic simulation testing.
//!
//! Invariants are properties that must always hold during system execution.
//! Unlike example-based tests that check specific scenarios, invariants
//! verify behavioral properties across all possible execution paths.
//!
//! # Architecture
//!
//! The invariant system extracts observable state from App and Bridge into
//! a [`SystemSnapshot`], then runs registered [`Invariant`] checks against it.
//! Violations trigger panics with detailed context for debugging.
//!
//! # Usage
//!
//! ```ignore
//! let registry = InvariantRegistry::standard();
//! let snapshot = SystemSnapshot::from_app(&app);
//! registry.check_all(&snapshot)?;
//! ```

mod checks;
mod snapshot;

pub use checks::{
    ActiveRoomInRooms, EpochMonotonicity, MembershipConsistency, TreeHashConvergence,
};
pub use snapshot::{ClientSnapshot, RoomSnapshot, SystemSnapshot};

/// Invariant check result.
pub type InvariantResult = Result<(), Violation>;

/// Invariant violation with context.
#[derive(Debug, Clone)]
pub struct Violation {
    /// Name of the violated invariant.
    pub invariant: &'static str,
    /// Description of what went wrong.
    pub message: String,
}

impl std::fmt::Display for Violation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.invariant, self.message)
    }
}

impl std::error::Error for Violation {}

/// An invariant that can be checked against system state.
///
/// Invariants are behavioral properties that must always hold.
/// They capture WHAT must be true, not specific test scenarios.
pub trait Invariant: Send + Sync {
    /// Invariant name for error reporting.
    fn name(&self) -> &'static str;

    /// Check the invariant against the current state.
    ///
    /// Returns `Ok(())` if the invariant holds, or a [`Violation`]
    /// describing what went wrong.
    fn check(&self, state: &SystemSnapshot) -> InvariantResult;
}

/// Registry of invariants to check.
///
/// Collects multiple invariants and runs them all against system state.
/// Use [`InvariantRegistry::standard()`] for common App/Bridge invariants.
pub struct InvariantRegistry {
    invariants: Vec<Box<dyn Invariant>>,
}

impl Default for InvariantRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl InvariantRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self { invariants: Vec::new() }
    }

    /// Create a registry with standard App/Bridge invariants.
    ///
    /// Includes:
    /// - [`ActiveRoomInRooms`]: active_room is in rooms map
    /// - [`EpochMonotonicity`]: epochs never decrease
    /// - [`MembershipConsistency`]: members agree on membership
    pub fn standard() -> Self {
        let mut registry = Self::new();
        registry.add(ActiveRoomInRooms);
        registry.add(EpochMonotonicity);
        registry.add(MembershipConsistency);
        registry
    }

    /// Add an invariant to the registry.
    pub fn add<I: Invariant + 'static>(&mut self, invariant: I) {
        self.invariants.push(Box::new(invariant));
    }

    /// Check all invariants against the given state.
    ///
    /// Returns `Ok(())` if all invariants hold, or all violations found.
    pub fn check_all(&self, state: &SystemSnapshot) -> Result<(), Vec<Violation>> {
        let violations: Vec<_> =
            self.invariants.iter().filter_map(|inv| inv.check(state).err()).collect();

        if violations.is_empty() { Ok(()) } else { Err(violations) }
    }

    /// Check all invariants, panicking on first violation.
    ///
    /// Use this in tests where you want immediate failure with context.
    pub fn assert_all(&self, state: &SystemSnapshot, context: &str) {
        if let Err(violations) = self.check_all(state) {
            let messages: Vec<_> = violations.iter().map(|v| v.to_string()).collect();
            panic!("Invariant violation {context}:\n  {}", messages.join("\n  "));
        }
    }

    /// Number of registered invariants.
    pub fn len(&self) -> usize {
        self.invariants.len()
    }

    /// Check if registry is empty.
    pub fn is_empty(&self) -> bool {
        self.invariants.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn standard_registry_has_invariants() {
        let registry = InvariantRegistry::standard();
        assert!(!registry.is_empty());
        assert_eq!(registry.len(), 3);
    }

    #[test]
    fn empty_snapshot_passes_invariants() {
        let registry = InvariantRegistry::standard();
        let snapshot = SystemSnapshot::empty();
        assert!(registry.check_all(&snapshot).is_ok());
    }
}
