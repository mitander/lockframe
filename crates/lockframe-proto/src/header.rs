//! Frame header implementation with zero-copy parsing.
//!
//! The `FrameHeader` is a fixed 128-byte structure that is serialized
//! as raw binary (Big Endian). This enables O(1) routing decisions
//! at the sequencer without deserialization overhead.

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use crate::{
    FrameFlags, Opcode,
    errors::{ProtocolError, Result},
};

/// Fixed 128-byte frame header (Big Endian network byte order)
///
/// All multi-byte integers are stored in Big Endian format to match network
/// byte order. Fields are stored as raw byte arrays to avoid alignment issues.
///
/// The header fits exactly two 64-byte CPU cache lines: bytes 0-63 contain all
/// routing/sequencing data (the sequencer can route frames touching only this
/// line), and bytes 64-127 contain the authentication signature (fetched only
/// during verification). This minimizes memory bandwidth and maximizes cache
/// locality for the O(1) routing hot path at 15K+ frames/sec.
///
/// # Security
///
/// The #[repr(C, packed)] layout with zerocopy traits ensures this struct can
/// be safely cast from untrusted network bytes - all 128-byte patterns are
/// valid, preventing undefined behavior. The signature field binds the entire
/// header to an MLS epoch. Verification happens separately after parsing to
/// allow routing before authentication. The `log_index` provides a monotonic
/// sequence number   per room. Combined with the `hlc_timestamp`, this prevents
/// replay attacks.
///
/// - Epoch Isolation: The `epoch` field ensures frames cannot be replayed
///   across different MLS group generations, even if the signature verifies.
#[repr(C, packed)]
#[derive(Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable)]
pub struct FrameHeader {
    // CACHE LINE 1: Routing/Sequencing (bytes 0-63)---

    // Protocol identification (8 bytes: 0-7)
    magic: [u8; 4],             // 0x4C4F4652 ("LOFR" in ASCII)
    version: u8,                // 0x01
    flags: u8,                  // FrameFlags bitfield
    pub(crate) opcode: [u8; 2], // u16 operation code

    // Request/payload metadata (8 bytes: 8-15)
    request_id: [u8; 4], // u32 client nonce (4B concurrent requests sufficient)
    pub(crate) payload_size: [u8; 4], // u32 payload length (moved for alignment)

    // Routing context (24 bytes: 16-39)
    room_id: [u8; 16],  // UUID (128-bit)
    sender_id: [u8; 8], // u64 sender identifier

    // Ordering/routing context (16 bytes: 40-55)
    // Opcode-dependent field:
    //   - Sequenced frames (AppMessage, Commit, Proposal): log_index (sequence number)
    //   - Welcome frames: recipient_id (target member for routing)
    context_id: [u8; 8],
    hlc_timestamp: [u8; 8], // u64 hybrid logical clock

    // MLS binding (8 bytes: 56-63)
    epoch: [u8; 8], // u64 MLS epoch (uniquely identifies key generation)

    // CACHE LINE 2: Authentication (bytes 64-127)

    // Authentication (64 bytes: 64-127)
    signature: [u8; 64], // Ed25519 signature
}

impl FrameHeader {
    /// Size of the serialized header (128 bytes)
    /// Fits exactly into two 64-byte CPU cache lines
    pub const SIZE: usize = 128;

    /// Magic number: "LOFR" in ASCII (0x4C4F4652)
    pub const MAGIC: u32 = 0x4C4F_4652;

    /// Current protocol version
    pub const VERSION: u8 = 0x01;

    /// Maximum payload size (16 MB)
    pub const MAX_PAYLOAD_SIZE: u32 = 16 * 1024 * 1024;

    /// Create a new header with the specified opcode.
    #[must_use]
    pub fn new(opcode: Opcode) -> Self {
        let mut bytes = [0u8; Self::SIZE];
        bytes[0..4].copy_from_slice(&Self::MAGIC.to_be_bytes());
        bytes[4] = Self::VERSION;
        bytes[6..8].copy_from_slice(&opcode.to_u16().to_be_bytes());

        // SAFETY: We just constructed valid bytes with correct magic and version.
        // from_bytes will validate these and return a valid header.
        Self::from_bytes(&bytes)
            .ok()
            .unwrap_or_else(|| unreachable!("constructed valid header with correct magic/version"))
            .to_owned()
    }

    /// Parse header from network bytes (zero-copy, safe)
    ///
    /// This function casts raw bytes directly to a `FrameHeader` reference
    /// using compile-time layout verification from `zerocopy`. No data is
    /// copied.
    ///
    /// # Errors
    ///
    /// - `ProtocolError::FrameTooShort` if buffer is too short (< 128 bytes)
    /// - `ProtocolError::InvalidMagic` if magic number is invalid
    /// - `ProtocolError::UnsupportedVersion` if protocol version is unsupported
    /// - `ProtocolError::PayloadTooLarge` if payload size exceeds maximum
    ///
    /// # Security
    ///
    /// - Zero-Copy Safety: The `zerocopy` crate verifies at compile-time that
    ///   `FrameHeader` has a stable memory layout. All bit patterns are valid
    ///   (no invalid representations), so casting arbitrary bytes cannot cause
    ///   undefined behavior.
    ///
    /// - Validation Order: We validate cheapest-to-check properties first
    ///   (size, magic) before more expensive ones (version, payload size). This
    ///   fails fast on garbage data.
    ///
    /// - No Signature Verification: This function does NOT verify the Ed25519
    ///   signature. Headers are structurally valid but not authenticated.
    ///   Signature verification happens later in the MLS layer.
    pub fn from_bytes(bytes: &[u8]) -> Result<&Self> {
        let header = Self::ref_from_prefix(bytes)
            .map_err(|_| ProtocolError::FrameTooShort {
                expected: Self::SIZE,
                actual: bytes.len(),
            })?
            .0;

        if u32::from_be_bytes(header.magic) != Self::MAGIC {
            return Err(ProtocolError::InvalidMagic);
        }

        if header.version != Self::VERSION {
            return Err(ProtocolError::UnsupportedVersion(header.version));
        }

        let payload_size = u32::from_be_bytes(header.payload_size);
        if payload_size > Self::MAX_PAYLOAD_SIZE {
            return Err(ProtocolError::PayloadTooLarge {
                size: payload_size as usize,
                max: Self::MAX_PAYLOAD_SIZE as usize,
            });
        }

        Ok(header)
    }

    /// Serialize header to bytes (zero-copy)
    #[must_use]
    pub fn to_bytes(&self) -> [u8; Self::SIZE] {
        let bytes = IntoBytes::as_bytes(self);
        let mut arr = [0u8; Self::SIZE];
        arr.copy_from_slice(bytes);
        arr
    }

    /// Protocol magic number (0x4C4F4652 = "LOFR").
    #[must_use]
    pub fn magic(&self) -> u32 {
        u32::from_be_bytes(self.magic)
    }

    /// Protocol version byte (currently 0x01).
    #[must_use]
    pub fn version(&self) -> u8 {
        self.version
    }

    /// Frame processing flags (compression, priority, etc.).
    #[must_use]
    pub fn flags(&self) -> FrameFlags {
        FrameFlags::from_byte(self.flags)
    }

    /// Operation code as raw u16.
    #[must_use]
    pub fn opcode(&self) -> u16 {
        u16::from_be_bytes(self.opcode)
    }

    /// Operation code as enum. `None` if unrecognized.
    #[must_use]
    pub fn opcode_enum(&self) -> Option<Opcode> {
        Opcode::from_u16(self.opcode())
    }

    /// Client-assigned nonce for request/response correlation.
    #[must_use]
    pub fn request_id(&self) -> u32 {
        u32::from_be_bytes(self.request_id)
    }

    /// 128-bit room UUID.
    #[must_use]
    pub fn room_id(&self) -> u128 {
        u128::from_be_bytes(self.room_id)
    }

    /// Room UUID as raw big-endian bytes.
    #[must_use]
    pub fn room_id_bytes(&self) -> &[u8; 16] {
        &self.room_id
    }

    /// Stable sender identifier (assigned during handshake).
    #[must_use]
    pub fn sender_id(&self) -> u64 {
        u64::from_be_bytes(self.sender_id)
    }

    /// Monotonic sequence number within this room's log.
    ///
    /// Only meaningful for sequenced opcodes (`AppMessage`, Commit, Proposal).
    /// For Welcome frames, use [`Self::recipient_id()`] instead.
    #[must_use]
    pub fn log_index(&self) -> u64 {
        debug_assert!(
            self.opcode_enum() != Some(Opcode::Welcome),
            "log_index() called on Welcome frame - use recipient_id() instead"
        );
        u64::from_be_bytes(self.context_id)
    }

    /// Target member for Welcome routing.
    ///
    /// Only meaningful for Welcome frames. For sequenced frames, use
    /// [`Self::log_index()`] instead.
    #[must_use]
    pub fn recipient_id(&self) -> u64 {
        debug_assert!(
            self.opcode_enum() == Some(Opcode::Welcome),
            "recipient_id() called on non-Welcome frame - use log_index() instead"
        );
        u64::from_be_bytes(self.context_id)
    }

    /// Hybrid Logical Clock timestamp for causality and replay protection.
    #[must_use]
    pub fn hlc_timestamp(&self) -> u64 {
        u64::from_be_bytes(self.hlc_timestamp)
    }

    /// MLS epoch number (increments on membership changes).
    #[must_use]
    pub fn epoch(&self) -> u64 {
        u64::from_be_bytes(self.epoch)
    }

    /// Payload size in bytes (max 16 MB).
    #[must_use]
    pub fn payload_size(&self) -> u32 {
        u32::from_be_bytes(self.payload_size)
    }

    /// Ed25519 signature over header fields.
    #[must_use]
    pub fn signature(&self) -> &[u8; 64] {
        &self.signature
    }

    /// Bytes to sign (excludes mutable `context_id` and signature itself).
    ///
    /// Returns bytes 0-39 + 48-63 (56 bytes total).
    #[must_use]
    pub fn signing_data(&self) -> [u8; 56] {
        let bytes = self.to_bytes();
        let mut data = [0u8; 56];
        data[..40].copy_from_slice(&bytes[..40]); // Bytes 0-39
        data[40..56].copy_from_slice(&bytes[48..64]); // Bytes 48-63
        data
    }

    /// Update room UUID.
    pub fn set_room_id(&mut self, room_id: u128) {
        self.room_id = room_id.to_be_bytes();
    }

    /// Assign log index (sequencer use only).
    ///
    /// Only valid for sequenced opcodes. For Welcome, use
    /// [`Self::set_recipient_id()`].
    pub fn set_log_index(&mut self, log_index: u64) {
        debug_assert!(
            self.opcode_enum() != Some(Opcode::Welcome),
            "set_log_index() called on Welcome frame - use set_recipient_id() instead"
        );
        self.context_id = log_index.to_be_bytes();
    }

    /// Set routing target for Welcome frames.
    ///
    /// Only valid for Welcome. For sequenced frames, use
    /// [`Self::set_log_index()`].
    pub fn set_recipient_id(&mut self, recipient_id: u64) {
        debug_assert!(
            self.opcode_enum() == Some(Opcode::Welcome),
            "set_recipient_id() called on non-Welcome frame - use set_log_index() instead"
        );
        self.context_id = recipient_id.to_be_bytes();
    }

    /// Update sender identifier.
    pub fn set_sender_id(&mut self, sender_id: u64) {
        self.sender_id = sender_id.to_be_bytes();
    }

    /// Update MLS epoch.
    pub fn set_epoch(&mut self, epoch: u64) {
        self.epoch = epoch.to_be_bytes();
    }

    /// Set Ed25519 signature (computed over [`Self::signing_data()`]).
    pub fn set_signature(&mut self, signature: [u8; 64]) {
        self.signature = signature;
    }

    /// Set client request nonce for response correlation.
    pub fn set_request_id(&mut self, request_id: u32) {
        self.request_id = request_id.to_be_bytes();
    }

    /// Update frame processing flags.
    pub fn set_flags(&mut self, flags: FrameFlags) {
        self.flags = flags.to_byte();
    }

    /// Set HLC timestamp for causality tracking.
    pub fn set_hlc_timestamp(&mut self, timestamp: u64) {
        self.hlc_timestamp = timestamp.to_be_bytes();
    }

    /// Set payload size (must be set before signing if signature is used).
    pub fn set_payload_size(&mut self, size: u32) {
        self.payload_size = size.to_be_bytes();
    }
}

// Manual Debug implementation (can't derive due to packed repr)
impl std::fmt::Debug for FrameHeader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let context_value = u64::from_be_bytes(self.context_id);
        let context_label =
            if self.opcode_enum() == Some(Opcode::Welcome) { "recipient_id" } else { "log_index" };

        f.debug_struct("FrameHeader")
            .field("magic", &format!("{:#010x}", self.magic()))
            .field("version", &self.version())
            .field("flags", &self.flags())
            .field("opcode", &format!("{:#06x}", self.opcode()))
            .field("request_id", &self.request_id())
            .field("room_id", &format!("{:#034x}", self.room_id()))
            .field("sender_id", &self.sender_id())
            .field(context_label, &context_value)
            .field("hlc_timestamp", &self.hlc_timestamp())
            .field("epoch", &self.epoch())
            .field("payload_size", &self.payload_size())
            .finish_non_exhaustive()
    }
}

// Manual PartialEq implementation (can't derive due to packed repr)
impl PartialEq for FrameHeader {
    fn eq(&self, other: &Self) -> bool {
        self.to_bytes() == other.to_bytes()
    }
}

impl Eq for FrameHeader {}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn arbitrary_bytes<const N: usize>() -> impl Strategy<Value = [u8; N]> {
        prop::collection::vec(any::<u8>(), N).prop_map(|v| {
            let mut arr = [0u8; N];
            arr.copy_from_slice(&v);
            arr
        })
    }

    impl Arbitrary for FrameHeader {
        type Parameters = ();
        type Strategy = BoxedStrategy<Self>;

        fn arbitrary_with((): Self::Parameters) -> Self::Strategy {
            (
                arbitrary_bytes::<2>(),        // opcode
                any::<u8>(),                   // flags
                arbitrary_bytes::<4>(),        // request_id (u32)
                arbitrary_bytes::<16>(),       // room_id
                arbitrary_bytes::<8>(),        // sender_id
                arbitrary_bytes::<8>(),        // context_id
                arbitrary_bytes::<8>(),        // hlc_timestamp
                arbitrary_bytes::<8>(),        // epoch
                0u32..=Self::MAX_PAYLOAD_SIZE, // payload_size
                arbitrary_bytes::<64>(),       // signature
            )
                .prop_map(
                    |(
                        opcode,
                        flags,
                        request_id,
                        room_id,
                        sender_id,
                        context_id,
                        hlc_timestamp,
                        epoch,
                        payload_size,
                        signature,
                    )| {
                        Self {
                            magic: Self::MAGIC.to_be_bytes(),
                            version: Self::VERSION,
                            flags,
                            opcode,
                            request_id,
                            payload_size: payload_size.to_be_bytes(),
                            room_id,
                            sender_id,
                            context_id,
                            hlc_timestamp,
                            epoch,
                            signature,
                        }
                    },
                )
                .boxed()
        }
    }

    #[test]
    fn header_size() {
        assert_eq!(std::mem::size_of::<FrameHeader>(), FrameHeader::SIZE);
        assert_eq!(FrameHeader::SIZE, 128);
    }

    proptest! {
        #[test]
        fn header_round_trip(header in any::<FrameHeader>()) {
            let bytes = header.to_bytes();
            let parsed = FrameHeader::from_bytes(&bytes).expect("should parse");
            prop_assert_eq!(&header, parsed);
        }

        #[test]
        fn header_accessors(header in any::<FrameHeader>()) {
            // Verify accessors return correct values
            prop_assert_eq!(header.magic(), FrameHeader::MAGIC);
            prop_assert_eq!(header.version(), FrameHeader::VERSION);
            prop_assert!(header.payload_size() <= FrameHeader::MAX_PAYLOAD_SIZE);
        }
    }

    #[test]
    fn reject_short_buffer() {
        let short_buf = [0u8; 100];
        let result = FrameHeader::from_bytes(&short_buf);
        assert_eq!(result, Err(ProtocolError::FrameTooShort { expected: 128, actual: 100 }));
    }

    #[test]
    fn reject_invalid_magic() {
        let mut buf = [0u8; 128];
        buf[0..4].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);
        buf[4] = FrameHeader::VERSION; // valid version

        let result = FrameHeader::from_bytes(&buf);
        assert_eq!(result, Err(ProtocolError::InvalidMagic));
    }

    #[test]
    fn reject_invalid_version() {
        let mut buf = [0u8; 128];
        buf[0..4].copy_from_slice(&FrameHeader::MAGIC.to_be_bytes());
        buf[4] = 0xFF; // invalid version

        let result = FrameHeader::from_bytes(&buf);
        assert_eq!(result, Err(ProtocolError::UnsupportedVersion(0xFF)));
    }

    #[test]
    fn reject_oversized_payload() {
        let mut buf = [0u8; 128];
        buf[0..4].copy_from_slice(&FrameHeader::MAGIC.to_be_bytes());
        buf[4] = FrameHeader::VERSION;

        // Set payload_size to exceed maximum (at offset 12-15)
        let oversized = FrameHeader::MAX_PAYLOAD_SIZE + 1;
        buf[12..16].copy_from_slice(&oversized.to_be_bytes());

        let result = FrameHeader::from_bytes(&buf);
        assert!(matches!(result, Err(ProtocolError::PayloadTooLarge { .. })));
    }
}
