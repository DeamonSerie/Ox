//! Currency symbol utilities and helpers for custom MVMS chains, mirroring `oxydome-gas`.

use oxydome_core::Amount;

/// Validates a custom currency symbol.
///
/// Rules:
/// - Must not be empty.
/// - Maximum 12 characters.
/// - Must consist solely of ASCII alphanumeric characters.
pub fn validate_currency_symbol(symbol: &str) -> Result<(), String> {
    if symbol.is_empty() {
        return Err("currency symbol cannot be empty".to_string());
    }
    if symbol.len() > 12 {
        return Err(format!(
            "currency symbol '{}' exceeds maximum length of 12 characters",
            symbol
        ));
    }
    if !symbol.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err(format!(
            "currency symbol '{}' contains non-alphanumeric characters",
            symbol
        ));
    }
    Ok(())
}

/// Derives the bech32m address Human-Readable Part (HRP) from the currency symbol.
pub fn address_prefix_for_symbol(symbol: &str) -> String {
    let lower = symbol.to_ascii_lowercase();
    if lower.is_empty() {
        "ox".to_string()
    } else {
        lower
    }
}

/// Formats an amount with the chain's currency symbol.
pub fn format_currency(amount: Amount, symbol: &str) -> String {
    format!("{} {}", amount, symbol)
}

/// Formats a Speedometer amount with the chain's gas denomination.
pub fn format_speedometer_currency(amount: Amount, symbol: &str) -> String {
    if symbol.eq_ignore_ascii_case("OX") {
        format!("{} SPEED", amount)
    } else {
        format!("{} {}-SPEED", amount, symbol)
    }
}

/// Scales an amount according to a relative reference price ratio.
pub fn scale_currency_amount(
    amount: Amount,
    new_reference_price: Amount,
    base_reference_price: Amount,
) -> Amount {
    if base_reference_price == 0 {
        return amount;
    }
    amount.saturating_mul(new_reference_price) / base_reference_price
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_currency_symbol() {
        assert!(validate_currency_symbol("OX").is_ok());
        assert!(validate_currency_symbol("MYGAS").is_ok());
        assert!(validate_currency_symbol("DOX").is_ok());
        assert!(validate_currency_symbol("").is_err());
        assert!(validate_currency_symbol("TOOLONGNAME123").is_err());
        assert!(validate_currency_symbol("OX-1").is_err());
    }

    #[test]
    fn test_address_prefix() {
        assert_eq!(address_prefix_for_symbol("OX"), "ox");
        assert_eq!(address_prefix_for_symbol("MYGAS"), "mygas");
        assert_eq!(address_prefix_for_symbol("TOX"), "tox");
    }

    #[test]
    fn test_format_helpers() {
        assert_eq!(format_currency(1000, "OX"), "1000 OX");
        assert_eq!(format_currency(500, "MYGAS"), "500 MYGAS");
        assert_eq!(format_speedometer_currency(100, "OX"), "100 SPEED");
        assert_eq!(format_speedometer_currency(100, "MYGAS"), "100 MYGAS-SPEED");
    }

    #[test]
    fn test_scale_currency_amount() {
        assert_eq!(scale_currency_amount(100, 2, 1), 200);
        assert_eq!(scale_currency_amount(100, 1, 2), 50);
        assert_eq!(scale_currency_amount(100, 5, 0), 100);
    }
}
