use pinocchio::pubkey::Pubkey;

#[derive(Clone, Debug)]
struct Settings {
    // Stored admin expected to control pause.
    owner: Pubkey,
    // Current paused flag.
    paused: bool,
}

fn vuln_toggle(settings: &mut Settings, _caller: Pubkey) {
    // Mirrors vulnerable handler: any signer can flip the switch.
    settings.paused = !settings.paused;
}

fn safe_toggle(settings: &mut Settings, caller: Pubkey) -> Result<bool, &'static str> {
    // Enforce owner identity before mutating state.
    if caller != settings.owner {
        return Err("unauthorized");
    }
    settings.paused = !settings.paused;
    Ok(settings.paused)
}

#[cfg(test)]
mod pinocchio_tests {
    use super::*;

    #[test]
    fn vuln_allows_any_signer_to_pause() {
        let owner = Pubkey::new_unique();
        let attacker = Pubkey::new_unique();
        let mut settings = Settings { owner, paused: false };

        vuln_toggle(&mut settings, attacker);

        assert!(settings.paused);
        assert_eq!(settings.owner, owner);
    }

    #[test]
    fn safe_requires_owner_signature() {
        let owner = Pubkey::new_unique();
        let mut settings = Settings { owner, paused: false };

        let err = safe_toggle(&mut settings, Pubkey::new_unique()).unwrap_err();
        assert_eq!(err, "unauthorized");
        assert!(!settings.paused);

        let paused = safe_toggle(&mut settings, owner).unwrap();
        assert!(paused);
        assert!(settings.paused);
    }
}
