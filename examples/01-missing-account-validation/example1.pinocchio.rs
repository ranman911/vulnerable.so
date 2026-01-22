rust
// example1.pinocchio.rs
//
// Pinocchio-based test for Missing Account Validation vulnerability
//
// This file demonstrates how to use Pinocchio as a library dependency
// to quickly test the vulnerable and fixed versions of the missing account
// validation program.
//
// Pinocchio provides fast, off-chain simulation without needing a full validator,
// making it ideal for rapid iteration during development.
use pinocchio::pubkey::Pubkey;

#[derive(Clone, Debug, PartialEq)]
struct DummyAccount {
    // Simulates the on-chain account owner (program id that controls the data).
    owner: Pubkey,
    // Stored authority field that should gate writes in the fixed flow.
    authority: Pubkey,
    // Backing bytes for the account; this is what gets clobbered in the vuln flow.
    data: Vec<u8>,
}

fn vuln_write(target: &mut DummyAccount, msg: &str) {
    // Mirrors the vulnerable handler: writes directly to raw bytes without owner/seed checks.
    target.data[..msg.len()].copy_from_slice(msg.as_bytes());
}

fn safe_write(target: &mut DummyAccount, authority: Pubkey, program_id: Pubkey, msg: &str) -> Result<(), &'static str> {
    // Enforce owner binding (Anchor's owner check on Account<T>).
    if target.owner != program_id {
        return Err("wrong owner");
    }
    // Enforce has_one-style authority binding.
    if target.authority != authority {
        return Err("wrong authority");
    }
    // Bound payload size like the fixed handler.
    if msg.len() > target.data.len() || msg.len() > 128 {
        return Err("message too long");
    }
    // Safe write once all guards pass.
    target.data[..msg.len()].copy_from_slice(msg.as_bytes());
    Ok(())
}

#[cfg(test)]
mod pinocchio_tests {
    use super::*;

    #[test]
    fn vulnerable_overwrites_foreign_account() {
        let program_a = Pubkey::new_unique();
        let program_b = Pubkey::new_unique();
        let mut foreign = DummyAccount {
            owner: program_b,
            authority: Pubkey::new_unique(),
            data: vec![0u8; 16],
        };

        vuln_write(&mut foreign, "hijack-admin");

        assert_eq!(&foreign.data[..11], b"hijack-admin");
        assert_eq!(foreign.owner, program_b);
    }

    #[test]
    fn safe_write_blocks_wrong_owner_and_authority() {
        let program = Pubkey::new_unique();
        let mut box_account = DummyAccount {
            owner: program,
            authority: Pubkey::new_unique(),
            data: vec![0u8; 16],
        };

        // Wrong authority
        let err = safe_write(&mut box_account, Pubkey::new_unique(), program, "ok").unwrap_err();
        assert_eq!(err, "wrong authority");

        // Oversized message
        let auth = box_account.authority;
        let err = safe_write(&mut box_account, auth, program, "a-very-long-message-that-exceeds").unwrap_err();
        assert_eq!(err, "message too long");

        // Correct path succeeds
        safe_write(&mut box_account, auth, program, "secure").unwrap();
        assert_eq!(&box_account.data[..6], b"secure");
    }
}