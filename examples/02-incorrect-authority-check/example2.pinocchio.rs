use pinocchio::pubkey::Pubkey;

#[derive(Clone, Debug, PartialEq)]
struct Config {
    // Stored admin expected to authorize updates.
    admin: Pubkey,
    // Basis points fee being mutated by the instruction.
    fee_bps: u16,
}

fn vuln_set_fee(cfg: &mut Config, _caller: Pubkey, new_fee: u16) {
    // Mirrors vulnerable logic: only checks that someone signed, not who.
    cfg.fee_bps = new_fee;
}

fn safe_set_fee(cfg: &mut Config, caller: Pubkey, new_fee: u16) -> Result<(), &'static str> {
    // Enforce admin identity (has_one binding).
    if caller != cfg.admin {
        return Err("unauthorized");
    }
    // Enforce business constraint on fee size.
    if new_fee > 10_000 {
        return Err("invalid fee");
    }
    cfg.fee_bps = new_fee;
    Ok(())
}

#[cfg(test)]
mod pinocchio_tests {
    use super::*;

    #[test]
    fn vuln_allows_attacker_fee_change() {
        let admin = Pubkey::new_unique();
        let attacker = Pubkey::new_unique();
        let mut cfg = Config { admin, fee_bps: 50 };

        vuln_set_fee(&mut cfg, attacker, 9_999);

        assert_eq!(cfg.fee_bps, 9_999);
        assert_eq!(cfg.admin, admin);
    }

    #[test]
    fn safe_enforces_admin_and_bounds() {
        let admin = Pubkey::new_unique();
        let mut cfg = Config { admin, fee_bps: 50 };

        let err = safe_set_fee(&mut cfg, Pubkey::new_unique(), 200).unwrap_err();
        assert_eq!(err, "unauthorized");
        assert_eq!(cfg.fee_bps, 50);

        let err = safe_set_fee(&mut cfg, admin, 20_000).unwrap_err();
        assert_eq!(err, "invalid fee");
        assert_eq!(cfg.fee_bps, 50);

        safe_set_fee(&mut cfg, admin, 250).unwrap();
        assert_eq!(cfg.fee_bps, 250);
    }
}
