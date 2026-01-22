use pinocchio::pubkey::Pubkey;

#[derive(Clone, Debug)]
struct VaultState {
    // Simulated vault lamport balance.
    balance: u64,
    // Reentrancy flag like the fix version's lock field.
    is_locked: bool,
    // Authority expected to authorize withdrawals.
    authority: Pubkey,
}

fn vuln_withdraw(state: &mut VaultState, amount: u64, attacker: impl FnOnce(&mut VaultState)) -> u64 {
    // Read state before CPI, enabling stale read for nested call.
    let snapshot = state.balance;
    // External call happens with state unchanged (attacker can mutate balance).
    attacker(state);
    // Original call resumes using stale snapshot and overwrites with stale math.
    let new_balance = snapshot.saturating_sub(amount);
    state.balance = new_balance;
    new_balance
}

fn safe_withdraw(
    state: &mut VaultState,
    caller: Pubkey,
    amount: u64,
    attacker: impl FnOnce(&mut VaultState) -> Result<(), &'static str>,
) -> Result<u64, &'static str> {
    // Enforce authority before doing anything else.
    if caller != state.authority {
        return Err("unauthorized");
    }
    // Prevent recursive entry.
    if state.is_locked {
        return Err("reentrancy");
    }

    // Lock and update state before external call (CEI pattern).
    state.is_locked = true;
    let original_balance = state.balance;
    let new_balance = state
        .balance
        .checked_sub(amount)
        .ok_or("insufficient funds")?;
    state.balance = new_balance;

    // Execute external hook; capture error for rollback.
    let attack_result = attacker(state);
    state.is_locked = false;

    if let Err(e) = attack_result {
        state.balance = original_balance; // Emulate transaction rollback on failure.
        return Err(e);
    }

    Ok(new_balance)
}

#[cfg(test)]
mod pinocchio_tests {
    use super::*;

    #[test]
    fn vuln_allows_double_spend_on_reentry() {
        let authority = Pubkey::new_unique();
        let mut state = VaultState {
            balance: 1_000,
            is_locked: false,
            authority,
        };

        let final_balance = vuln_withdraw(&mut state, 100, |s| {
            // Attacker re-enters and withdraws 500 before the outer call updates.
            s.balance = s.balance.saturating_sub(500);
        });

        assert_eq!(final_balance, 900);
        assert_eq!(state.balance, 900);
        // Correct CEI flow would land at 400 after two withdrawals.
        assert_ne!(state.balance, 400);
    }

    #[test]
    fn safe_blocks_reentrancy_and_checks_owner() {
        let authority = Pubkey::new_unique();
        let mut state = VaultState {
            balance: 1_000,
            is_locked: false,
            authority,
        };

        // Wrong signer is rejected.
        let err = safe_withdraw(&mut state, Pubkey::new_unique(), 50, |_| Ok(())).unwrap_err();
        assert_eq!(err, "unauthorized");
        assert_eq!(state.balance, 1_000);

        // Re-entrant attempt is blocked and rolled back.
        let err = safe_withdraw(&mut state, authority, 500, |s| {
            if s.is_locked {
                return Err("locked");
            }
            s.balance = s.balance.saturating_sub(500);
            Ok(())
        })
        .unwrap_err();
        assert_eq!(err, "locked");
        assert_eq!(state.balance, 1_000);
        assert!(!state.is_locked);

        // Happy path succeeds.
        let new_balance = safe_withdraw(&mut state, authority, 100, |_| Ok(())).unwrap();
        assert_eq!(new_balance, 900);
        assert_eq!(state.balance, 900);
        assert!(!state.is_locked);
    }
}
