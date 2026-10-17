// Currency Derivative Calculator
// Calculates micro token value from source currency price
// Used for determining micro token value after bridge transaction

use serde::{Deserialize, Serialize};

/// Currency price information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CurrencyPrice {
    /// Base currency symbol (e.g., "OXD")
    pub symbol: String,
    /// Price in USD
    pub price_usd: u64,
    /// Price timestamp
    pub timestamp: u64,
    /// Currency decay factor (for deflationary currencies)
    pub decay_factor: u64,
}

/// Micro token value calculation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MicroTokenValue {
    /// Original currency amount
    pub original_amount: u64,
    /// Derived micro token amount
    pub micro_amount: u64,
    /// Conversion rate used
    pub conversion_rate: u64,
    /// Calculation timestamp
    pub timestamp: u64,
}

/// Calculate micro token value from currency price
pub fn calculate_micro_value(original_amount: u64, price: &CurrencyPrice) -> MicroTokenValue {
    // Conversion rate: 1 original token = 1 micro token (1:1 parity)
    // Value is derived from the currency's USD price
    let conversion_rate = if price.price_usd > 0 {
        price.price_usd
    } else {
        1 // Default to 1 if no price data
    };

    let micro_amount = original_amount; // 1:1 parity for bridged tokens
    MicroTokenValue {
        original_amount,
        micro_amount,
        conversion_rate,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    }
}

/// Get derivative-adjusted supply
/// The micro token value changes based on the underlying currency's price
pub fn get_derivative_supply(base_supply: u64, price_change_percentage: u64) -> u64 {
    // Apply price change percentage to supply
    if price_change_percentage > 100 {
        // Price increased - supply effectively decreases
        base_supply.saturating_sub(base_supply * price_change_percentage / 100)
    } else {
        // Price decreased - supply effectively increases
        base_supply + (base_supply * price_change_percentage / 100)
    }
}

/// Adjust micro token supply based on market conditions
pub fn adjust_micro_supply(
    current_supply: u64,
    market_data: &[f64; 3], // [price, volume, market_cap]
) -> u64 {
    // Simple adjustment based on price change
    if market_data[0] > 0.0 {
        let price_change = market_data[0] / market_data[1]; // price/volume ratio
        let adjustment = (current_supply as f64 * price_change).round() as u64;
        saturating_add(current_supply, adjustment)
    } else {
        current_supply
    }
}

/// Saturing add helper
fn saturating_add(a: u64, b: u64) -> u64 {
    let result = a.checked_add(b);
    match result {
        Some(r) => r,
        // Wrap around on overflow - in production, handle error
        a => {
            todo!()
        }
    }
}
