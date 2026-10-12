// Bridge State Tracker
// Tracks bridge transaction status per OVM/OHM pair
// Validates bridge completion before micro token release

use serde::{Deserialize, Serialize};

/// Bridge state structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeState {
    /// Origin DAO / OVM address
    pub origin_dao: String,
    /// Destination DAO / OHM address
    pub destination_dao: String,
    /// Original token contract address
    pub token_address: String,
    /// Amount being bridged
    pub amount: u64,
    /// Whether bridge is finalized
    pub completed: bool,
    /// Unique bridge identifier
    pub bridge_id: u64,
    /// Timestamp of bridge creation
    pub created_at: u64,
    /// Whether original tokens have been transferred to destination chain
    pub original_tokens_transferred: bool,
}

/// Bridge metadata structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeMetadata {
    /// Bridge ID
    pub bridge_id: u64,
    /// Bridge amount
    pub amount: u64,
    /// Bridge timestamp
    pub timestamp: u64,
    /// Whether bridge validation is complete
    pub validated: bool,
}

/// Bridge error types
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum BridgeError {
    /// Bridge not found
    #[error("Bridge not found")]
    NotFound,
    /// Bridge already completed
    #[error("Bridge already completed")]
    AlreadyCompleted,
    /// Bridge not validated
    #[error("Bridge not validated")]
    NotValidated,
    /// Insufficient amount
    #[error("Insufficient amount")]
    InsufficientAmount,
    /// Bridge not authorized
    #[error("Bridge not authorized")]
    NotAuthorized,
}

/// Bridge result type
pub type BridgeResult<T> = Result<T, BridgeError>;

/// Bridge state storage (in production would use persistent storage)
pub struct BridgeStateStore {
    /// Mapping of bridge IDs to states
    pub bridges: std::collections::HashMap<u64, BridgeState>,
    /// Counter for generating bridge IDs
    pub next_bridge_id: u64,
}

impl BridgeStateStore {
    /// Create a new bridge state store
    pub fn new() -> Self {
        BridgeStateStore {
            bridges: std::collections::HashMap::new(),
            next_bridge_id: 1,
        }
    }

    /// Create a new bridge transaction
    pub fn create_bridge(
        &mut self,
        origin_dao: String,
        destination_dao: String,
        token_address: String,
        amount: u64,
    ) -> BridgeResult<u64> {
        let bridge_id = self.next_bridge_id;
        self.next_bridge_id += 1;

        let state = BridgeState {
            origin_dao,
            destination_dao,
            token_address,
            amount,
            completed: false,
            bridge_id,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            original_tokens_transferred: false,
        };

        self.bridges.insert(bridge_id, state);
        Ok(bridge_id)
    }

    /// Get bridge state by ID
    pub fn get_bridge(&self, bridge_id: u64) -> Option<&BridgeState> {
        self.bridges.get(&bridge_id)
    }

    /// Complete a bridge transaction
    /// 
    /// **Change**: Now also marks original tokens as transferred
    pub fn complete_bridge(&mut self, bridge_id: u64) -> BridgeResult<()> {
        let bridge = self.bridges.get(&bridge_id).ok_or(BridgeError::NotFound)?;
        if bridge.completed { return Err(BridgeError::AlreadyCompleted); };

        // Update bridge state
        let mut bridge = bridge.clone();
        bridge.completed = true;
        bridge.original_tokens_transferred = true;
        self.bridges.insert(bridge_id, bridge);

        Ok(())
    }

    /// Validate a bridge transaction
    pub fn validate_bridge(&mut self, bridge_id: u64) -> BridgeResult<()> {
        let bridge = self.bridges.get(&bridge_id).ok_or(BridgeError::NotFound)?;
        if bridge.completed { return Err(BridgeError::AlreadyCompleted); };
        // In production, would add validation logic here
        Ok(())
    }
}
