//! Oracle functions for scenario verification.
//!
//! Oracle functions run at the end of scenarios to verify global consistency.
//! They receive a snapshot of the entire world state and assert invariants.

use crate::scenario::World;

/// Oracle function type.
///
/// Receives immutable reference to world state and returns:
/// - `Ok(())` if all invariants hold
/// - `Err(message)` if verification fails
///
/// Generic over `I` (Instant type) to support virtual time in tests.
pub type OracleFn<I = std::time::Instant> = Box<dyn FnOnce(&World<I>) -> Result<(), String>>;

/// Create an oracle that verifies all actors are authenticated.
pub fn all_authenticated() -> OracleFn {
    Box::new(|world| {
        if world.all_authenticated() {
            Ok(())
        } else {
            Err("Not all actors are authenticated".to_string())
        }
    })
}

/// Create an oracle that verifies all actors have matching session IDs.
pub fn session_ids_match() -> OracleFn {
    Box::new(|world| {
        if world.session_ids_match() {
            Ok(())
        } else {
            Err("Session IDs do not match across actors".to_string())
        }
    })
}

/// Combine multiple oracles into one.
pub fn all_of(oracles: Vec<OracleFn>) -> OracleFn {
    Box::new(move |world| {
        for oracle in oracles {
            oracle(world)?;
        }
        Ok(())
    })
}
