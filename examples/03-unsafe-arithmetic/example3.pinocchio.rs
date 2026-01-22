fn vuln_withdraw(balance: u64, amount: u64) -> u64 {
    // Mirrors release-mode subtraction in the vulnerable handler (wraps on underflow).
    balance.wrapping_sub(amount)
}

fn safe_withdraw(balance: u64, amount: u64) -> Result<u64, &'static str> {
    // Uses checked_sub to return an error instead of wrapping.
    balance.checked_sub(amount).ok_or("insufficient funds")
}

#[cfg(test)]
mod pinocchio_tests {
    use super::*;

    #[test]
    fn vuln_wraps_to_max_on_underflow() {
        let result = vuln_withdraw(10, 11);
        assert_eq!(result, u64::MAX);
    }

    #[test]
    fn safe_blocks_underflow_and_allows_valid_withdrawals() {
        let err = safe_withdraw(10, 11).unwrap_err();
        assert_eq!(err, "insufficient funds");

        let ok = safe_withdraw(10, 5).unwrap();
        assert_eq!(ok, 5);
    }
}
