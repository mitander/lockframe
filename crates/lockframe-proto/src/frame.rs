//! Frame type combining header and payload.
//!
//! A `Frame` is the transport-layer packet consisting of:
//! - 128-byte raw binary header (Big Endian) for O(1) routing
//! - Variable-length raw bytes (already encoded)
//!
//! This is a pure data holder (header + bytes). For high-level logic,
//! see `Payload::into_frame()` and `Payload::from_frame()`.

use bytes::{BufMut, Bytes};

use crate::{
    FrameHeader,
    errors::{ProtocolError, Result},
};

/// Complete protocol frame (transport layer)
///
/// Layout on the wire:
/// `[FrameHeader: 128 bytes, raw binary] + [payload: variable bytes]`
///
/// Holds raw bytes, NOT the Payload enum. The server can route frames without
/// deserializing the payload.
///
/// # Invariants
///
/// - Size Consistency: `payload.len()` MUST match `header.payload_size()`. This
///   invariant is enforced by [`Frame::new`] and verified by [`Frame::decode`].
///
/// - Size Limit: `payload.len()` MUST NOT exceed
///   [`FrameHeader::MAX_PAYLOAD_SIZE`] (16 MB). Violations are rejected during
///   construction and encoding.
///
/// # Security
///
/// Provides structural validity only. Guarantees valid header format (magic
/// number, version, size limits) and that payload size matches header claim.
/// Does NOT guarantee authentication (signature verification must be done
/// separately) or decryption (payload may be ciphertext).
/// - CBOR validity (payload deserialization happens later)
///
/// For authenticated content, the signature in `header.signature()` must be
/// verified against the MLS epoch before trusting the payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// Frame header (128 bytes)
    pub header: FrameHeader,

    /// Raw payload bytes (already CBOR-encoded)
    pub payload: Bytes,
}

impl Frame {
    /// Create a new frame with automatic payload_size calculation
    ///
    /// The header's `payload_size` field is automatically set to match
    /// the actual payload length, ensuring consistency.
    ///
    /// # Panics
    ///
    /// Panics if `payload.len() > u32::MAX`. In practice, this cannot happen
    /// because `Bytes` is bounded by `isize::MAX` which is smaller than
    /// `u32::MAX` on all supported platforms.
    ///
    /// # Security
    ///
    /// - Size Enforcement: The payload size is set automatically, making it
    ///   impossible to create a Frame with mismatched header and payload sizes.
    ///   This prevents desynchronization attacks where the header claims a
    ///   different size than the payload.
    ///
    /// - No Validation: This constructor does NOT validate that payload size is
    ///   under [`FrameHeader::MAX_PAYLOAD_SIZE`]. Oversized frames will be
    ///   rejected later during [`Frame::encode`]. This design allows
    ///   constructing frames for testing without artificial size restrictions.
    #[must_use]
    pub fn new(mut header: FrameHeader, payload: impl Into<Bytes>) -> Self {
        let payload = payload.into();

        // INVARIANT: Payload length always fits in u32 because:
        // 1. Bytes is bounded by isize::MAX (Rust allocation limit)
        // 2. MAX_PAYLOAD_SIZE (16MB) << u32::MAX (4GB)
        // 3. Even on 64-bit, practical allocations never approach u32::MAX
        #[allow(clippy::expect_used)]
        let payload_len = u32::try_from(payload.len()).expect(
            "invariant: payload length fits in u32 (bounded by isize::MAX and protocol limit)",
        );

        header.payload_size = payload_len.to_be_bytes();

        debug_assert_eq!(header.payload_size(), payload_len);

        Self { header, payload }
    }

    /// Encode frame into buffer (simple copy, no magic)
    ///
    /// Writes: `[header (128 bytes)] + [payload (variable)]`
    ///
    /// # Errors
    ///
    /// - `ProtocolError::PayloadTooLarge` if payload exceeds MAX_PAYLOAD_SIZE
    ///   (16 MB)
    ///
    /// # Security
    ///
    /// - Size Limit Enforcement: This is the enforcement point for the 16 MB
    ///   payload limit. Frames exceeding this size are rejected to prevent
    ///   memory exhaustion DoS attacks.
    ///
    /// - No Serialization: This function performs simple memory copies with no
    ///   parsing or transformation. There are no opportunities for injection or
    ///   corruption.
    pub fn encode(&self, dst: &mut impl BufMut) -> Result<()> {
        debug_assert_eq!(self.payload.len(), self.header.payload_size() as usize);

        if self.payload.len() > FrameHeader::MAX_PAYLOAD_SIZE as usize {
            return Err(ProtocolError::PayloadTooLarge {
                size: self.payload.len(),
                max: FrameHeader::MAX_PAYLOAD_SIZE as usize,
            });
        }

        dst.put_slice(&self.header.to_bytes());
        dst.put_slice(&self.payload);

        Ok(())
    }

    /// Decode frame from wire format
    ///
    /// Returns a Frame with raw bytes (does NOT deserialize payload).
    /// Use `Payload::from_frame()` if you need the high-level enum.
    ///
    /// # Errors
    ///
    /// - `ProtocolError` if header parsing fails (invalid magic, version, or
    ///   size limits)
    /// - `ProtocolError::FrameTooShort` if payload is truncated (fewer bytes
    ///   than header claims)
    ///
    /// # Security
    ///
    /// - Fail Fast: All validation happens before allocating memory for the
    ///   payload. Malformed headers are rejected without copying data.
    ///
    /// - Exact Size: We only read exactly `payload_size` bytes from the buffer.
    ///   Trailing data is ignored, preventing buffer over-read.
    ///
    /// - No Deserialization: This function does NOT parse CBOR. It only
    ///   validates structural framing. Payload deserialization happens later
    ///   with explicit error handling.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let header = FrameHeader::from_bytes(bytes)?;

        let payload_size = header.payload_size() as usize;
        let total_size = FrameHeader::SIZE.checked_add(payload_size).ok_or({
            ProtocolError::PayloadTooLarge {
                size: payload_size,
                max: FrameHeader::MAX_PAYLOAD_SIZE as usize,
            }
        })?;

        debug_assert!(total_size >= FrameHeader::SIZE);

        if bytes.len() < total_size {
            #[cfg_attr(not(fuzzing), allow(unexpected_cfgs))]
            #[cfg(fuzzing)]
            {
                let _ = payload_size; // Proves we hit this branch
            }

            return Err(ProtocolError::FrameTruncated {
                expected: payload_size,
                actual: bytes.len().saturating_sub(FrameHeader::SIZE),
            });
        }

        #[cfg_attr(not(fuzzing), allow(unexpected_cfgs))]
        #[cfg(fuzzing)]
        {
            let _ = total_size; // Proves we hit success path
        }

        // INVARIANT: We've validated bytes.len() >= total_size in the truncation check
        // above. This slice operation cannot panic because:
        // - total_size = FrameHeader::SIZE + payload_size (checked arithmetic)
        // - We verified bytes.len() >= total_size in the preceding check
        // - Therefore: FrameHeader::SIZE < total_size <= bytes.len()
        #[allow(clippy::expect_used)]
        let payload = Bytes::copy_from_slice(
            bytes.get(FrameHeader::SIZE..total_size).expect("invariant: bounds checked above"),
        );

        debug_assert_eq!(payload.len(), payload_size);

        Ok(Self { header: *header, payload })
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::Opcode;

    impl Arbitrary for Frame {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with((): Self::Parameters) -> Self::Strategy {
            (any::<FrameHeader>(), any::<Vec<u8>>())
                .prop_map(|(header, payload_bytes)| Self::new(header, payload_bytes))
                .boxed()
        }
    }

    proptest! {
        #[test]
        fn frame_round_trip(frame in any::<Frame>()) {
            let mut wire = Vec::new();
            frame.encode(&mut wire).expect("should encode");

            let parsed = Frame::decode(&wire).expect("should decode");
            prop_assert_eq!(frame.payload, parsed.payload);
        }
    }

    #[test]
    fn frame_with_payload() {
        // Create valid header
        let mut bytes = [0u8; 128];
        bytes[0..4].copy_from_slice(&FrameHeader::MAGIC.to_be_bytes());
        bytes[4] = FrameHeader::VERSION;
        let mut header = *FrameHeader::from_bytes(&bytes).unwrap();
        header.opcode = Opcode::Ping.to_u16().to_be_bytes();

        // Create frame (payload_size set automatically)
        let payload_bytes = vec![1, 2, 3, 4];
        let frame = Frame::new(header, payload_bytes.clone());

        // Verify payload_size was set correctly
        #[allow(clippy::cast_possible_truncation)] // Test with small payload
        let expected_size = payload_bytes.len() as u32;
        assert_eq!(frame.header.payload_size(), expected_size);

        // Encode and decode
        let mut wire = Vec::new();
        frame.encode(&mut wire).expect("should encode");

        let parsed = Frame::decode(&wire).expect("should decode");
        assert_eq!(frame.payload, parsed.payload);
    }

    #[test]
    fn reject_truncated_frame() {
        // Create header claiming 100 bytes of payload
        let mut bytes = [0u8; 128];
        bytes[0..4].copy_from_slice(&FrameHeader::MAGIC.to_be_bytes());
        bytes[4] = FrameHeader::VERSION;

        let mut header = *FrameHeader::from_bytes(&bytes).unwrap();
        header.payload_size = 100u32.to_be_bytes();

        let header_bytes = header.to_bytes();

        // Only provide header, no payload
        let result = Frame::decode(&header_bytes);
        assert!(matches!(result, Err(ProtocolError::FrameTruncated { .. })));
    }
}
