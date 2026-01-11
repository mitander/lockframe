//! Deterministic simulation harness for Lockframe protocol testing.
//!
//! Turmoil-based implementations of the Environment and Transport traits for
//! deterministic, reproducible testing under various network conditions.
//!
//! # Model-Based Testing
//!
//! The `model` module provides a reference implementation for model-based
//! testing. Operations are applied to both the model and real implementation,
//! and their observable states are compared.
//!
//! # Invariant Testing
//!
//! The `invariants` module provides behavioral testing through invariant
//! checks. Invariants verify WHAT must be true across all execution paths, not
//! specific scenarios. Use [`InvariantRegistry::standard()`] for common
//! App/Bridge invariants.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod invariants;
pub mod model;
pub mod scenario;
pub mod sim_driver;
pub mod sim_env;
pub mod sim_server;
pub mod sim_transport;

pub use invariants::{
    ActiveRoomInRooms, ClientSnapshot, EpochMonotonicity, Invariant, InvariantRegistry,
    InvariantResult, MembershipConsistency, RoomSnapshot, SystemSnapshot, TreeHashConvergence,
    Violation,
};
pub use model::{
    ClientId, ErrorProperties, ModelClient, ModelMessage, ModelRoomId, ModelServer, ModelWorld,
    ObservableState, Operation, OperationError, OperationResult, PendingMessage, SmallMessage,
};
pub use sim_driver::SimDriver;
pub use sim_env::SimEnv;
pub use sim_server::{SharedSimServer, SimServer, create_shared_server};
pub use sim_transport::SimTransport;
