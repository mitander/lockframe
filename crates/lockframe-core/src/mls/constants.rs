//! MLS protocol constants
//!
//! Constants used for MLS validation and protocol limits.

/// Maximum epoch number (sanity limit to prevent overflow)
///
/// This limit prevents:
/// - Integer overflow in epoch arithmetic
/// - Extremely long-running groups that might have key exhaustion
/// - Malicious frames claiming unreasonably high epochs
///
/// At 1 epoch/hour, this allows ~114 years of operation.
/// Real deployments will likely rotate groups much more frequently.
pub const MAX_EPOCH: u64 = 1_000_000;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::assertions_on_constants, reason = "sanity check")]
    fn max_epoch_is_reasonable() {
        // Verify MAX_EPOCH is large enough for realistic usage
        const HOURS_PER_YEAR: u64 = 24 * 365;
        const MIN_YEARS: u64 = 100;

        assert!(
            MAX_EPOCH >= HOURS_PER_YEAR * MIN_YEARS,
            "MAX_EPOCH should allow at least {MIN_YEARS} years at 1 epoch/hour"
        );
    }

    #[test]
    fn max_epoch_prevents_overflow() {
        // Verify MAX_EPOCH + reasonable increment doesn't overflow
        assert!(MAX_EPOCH.checked_add(1000).is_some(), "MAX_EPOCH should allow safe arithmetic");
    }
}
