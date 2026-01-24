//! Scenario builder API.
//!
//! Provides a declarative API for constructing scenario tests that enforce
//! the Oracle Pattern.

use std::time::Duration;

use lockframe_core::{
    connection::{Connection, ConnectionAction, ConnectionConfig},
    env::Environment,
};
use tokio::time::Instant;

use crate::{
    SimEnv,
    scenario::{OracleFn, World},
};

/// Scenario builder.
///
/// Construct a scenario by configuring client and server, optionally
/// advancing time, and adding an oracle verification function.
pub struct Scenario {
    client_config: ConnectionConfig,
    server_config: ConnectionConfig,
    time_advance: Option<Duration>,
}

impl Scenario {
    /// Create a new scenario with default configuration.
    pub fn new() -> Self {
        Self {
            client_config: ConnectionConfig::default(),
            server_config: ConnectionConfig::default(),
            time_advance: None,
        }
    }

    /// Configure the client connection.
    pub fn with_client_config(mut self, config: ConnectionConfig) -> Self {
        self.client_config = config;
        self
    }

    /// Configure the server connection.
    pub fn with_server_config(mut self, config: ConnectionConfig) -> Self {
        self.server_config = config;
        self
    }

    /// Advance virtual time after handshake completion.
    ///
    /// This allows testing timeout behavior. The scenario will:
    /// 1. Execute the handshake
    /// 2. Advance time by the specified duration
    /// 3. Call tick() on both connections
    /// 4. Process any resulting actions (Close, SendFrame, etc.)
    /// 5. Run the oracle
    pub fn with_time_advance(mut self, duration: Duration) -> Self {
        self.time_advance = Some(duration);
        self
    }

    /// Set the oracle function and return a runnable scenario.
    ///
    /// The oracle is mandatory - you cannot run a scenario without
    /// verification.
    pub fn oracle(self, oracle: OracleFn<Instant>) -> RunnableScenario {
        RunnableScenario { scenario: self, oracle }
    }
}

impl Default for Scenario {
    fn default() -> Self {
        Self::new()
    }
}

/// A scenario with an oracle function that can be executed.
pub struct RunnableScenario {
    scenario: Scenario,
    oracle: OracleFn<Instant>,
}

impl RunnableScenario {
    /// Execute the scenario.
    ///
    /// Performs a complete handshake between client and server:
    /// 1. Client sends Hello
    /// 2. Server handles Hello and sends HelloReply
    /// 3. Client handles HelloReply and transitions to Authenticated
    ///
    /// If time_advance is set, advances time and calls tick() on both
    /// connections to process timeouts and heartbeats.
    ///
    /// Finally, the oracle is invoked to verify global consistency.
    pub fn run(self) -> Result<(), String> {
        let mut world: World<Instant> = World::new();
        let env = SimEnv::new();
        let now = env.now();

        let client = Connection::new(now, self.scenario.client_config.clone());
        let mut server = Connection::new(now, self.scenario.server_config.clone());
        server.set_session_id(0x1000_0000_0000_0000);

        world.set_client(client);
        world.set_server(server);

        self.execute_handshake(&mut world, now)?;

        if let Some(advance) = self.scenario.time_advance {
            let future = now + advance;
            self.tick_connections(&mut world, future)?;
        }

        (self.oracle)(&world)?;

        Ok(())
    }

    /// Execute the handshake between client and server.
    fn execute_handshake(&self, world: &mut World<Instant>, now: Instant) -> Result<(), String> {
        let hello_frame = {
            let client = world.client_mut();
            let actions =
                client.send_hello(now).map_err(|e| format!("client send_hello failed: {}", e))?;

            match actions.as_slice() {
                [ConnectionAction::SendFrame(frame)] => frame.clone(),
                _ => return Err("client send_hello returned unexpected actions".to_string()),
            }
        };

        world.record_client_frame_sent();
        world.record_server_frame_received();

        let hello_reply_frame = {
            let server = world.server_mut();
            let actions = server
                .handle_frame(&hello_frame, now)
                .map_err(|e| format!("server handle_frame(Hello) failed: {}", e))?;

            match actions.as_slice() {
                [ConnectionAction::SendFrame(frame)] => frame.clone(),
                _ => {
                    return Err(
                        "server handle_frame(Hello) returned unexpected actions".to_string()
                    );
                },
            }
        };

        world.record_server_frame_sent();
        world.record_client_frame_received();

        {
            let client = world.client_mut();
            let actions = client
                .handle_frame(&hello_reply_frame, now)
                .map_err(|e| format!("client handle_frame(HelloReply) failed: {}", e))?;

            if !actions.is_empty() {
                return Err(
                    "client handle_frame(HelloReply) returned unexpected actions".to_string()
                );
            }
        }

        Ok(())
    }

    /// Tick both connections at the given time and process resulting actions.
    fn tick_connections(&self, world: &mut World<Instant>, now: Instant) -> Result<(), String> {
        let client_actions = world.client_mut().tick(now);
        self.process_actions(world, Actor::Client, client_actions)?;

        let server_actions = world.server_mut().tick(now);
        self.process_actions(world, Actor::Server, server_actions)?;

        Ok(())
    }

    /// Process actions returned by tick() or other connection methods.
    fn process_actions(
        &self,
        world: &mut World<Instant>,
        actor: Actor,
        actions: Vec<ConnectionAction>,
    ) -> Result<(), String> {
        for action in actions {
            match action {
                ConnectionAction::Close { .. } => {
                    // Connection closed - this is expected for timeout tests
                    // Oracle will verify the state
                },
                ConnectionAction::SendFrame(_frame) => {
                    // Record frame sent
                    match actor {
                        Actor::Client => world.record_client_frame_sent(),
                        Actor::Server => world.record_server_frame_sent(),
                    }
                },
            }
        }
        Ok(())
    }
}

/// Actor identifier for action processing.
enum Actor {
    Client,
    Server,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scenario_requires_oracle() {
        // This should compile - oracle provided
        let _scenario = Scenario::new().oracle(Box::new(|_world| Ok(())));
    }

    #[test]
    fn scenario_creates_connections() {
        let scenario = Scenario::new().oracle(Box::new(|world| {
            // Both client and server should exist
            let _client = world.client();
            let _server = world.server();
            Ok(())
        }));

        scenario.run().expect("scenario should succeed");
    }
}
