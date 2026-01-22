use anchor_lang::prelude::*;

declare_id!("Fg6PaFpoGXkYsidMpWxTWqkWg5Rdp2q6uNQqynEWsJvj");

#[program]
pub mod missing_account_vuln {
    use super::*;

    pub fn set_message(ctx: Context<SetMessageVuln>, msg: String) -> Result<()> {
        // --- STEP 1: LACK OF OWNERSHIP VERIFICATION ---
        // We are using `try_borrow_mut_data()` on a raw AccountInfo. 
        // Anchor does NOT check if this program actually owns the account 'any_unchecked'.
        // BUG: An attacker can pass an account owned by a DIFFERENT program (e.g., a System Account or 
        // a different protocol's state account). If that account is marked as 'writable' in the 
        // transaction, this program will attempt to overwrite its data.
        let mut data = ctx.accounts.any_unchecked.try_borrow_mut_data()?;

        // --- STEP 2: LACK OF TYPE/DISCRIMINATOR VALIDATION ---
        // Normal Anchor 'Account' types have an 8-byte discriminator to ensure you aren't 
        // treating a "UserAccount" as a "ConfigAccount". 
        // BUG: Since we used 'AccountInfo', we are skipping that check. We are now 
        // treating the raw bytes of the account as a generic buffer. We have no idea 
        // what this account is supposed to represent.
        
        // --- STEP 3: LACK OF SIGNER VALIDATION ---
        // Usually, you want to ensure the person calling the function has permission.
        // BUG: There is no check to see if 'any_unchecked.key()' belongs to the person 
        // signing the transaction. Anyone can pass ANY account address they want here.

        // --- STEP 4: ARBITRARY MEMORY OVERWRITE ---
        // BUG: This line performs a raw slice copy. 
        // 1. If 'msg' is longer than the account's data buffer, the program will Panic (DoS).
        // 2. If 'msg' is shorter, it overwrites the start of the account and leaves 
        //    the rest of the original data intact, potentially creating "corrupted state"
        //    where the first few bytes are a string and the rest are old administrative keys.
        data[..msg.len()].copy_from_slice(msg.as_bytes());

        // --- THE ATTACK SCENARIO ---
        // 1. The attacker identifies a "TreasuryConfig" account owned by this program.
        // 2. The attacker calls 'set_message' and passes the "TreasuryConfig" address as 'any_unchecked'.
        // 3. The attacker provides a 'msg' that, when written to bytes, corresponds to 
        //    their own Public Key in the "admin" slot of that config account.
        // 4. The program blindly overwrites the config. The attacker is now the admin.
        
        Ok(())
    }
}

#[derive(Accounts)]
pub struct SetMessageVuln<'info> {
    // --- STEP 0: THE ROOT CAUSE ---
    // Using 'AccountInfo' or 'UncheckedAccount' tells Anchor: "Don't perform any safety checks."
    // By adding the #[account(mut)] attribute, we are only telling Solana the account 
    // needs to be writable. We are NOT validating WHO can write to it or WHAT it is.
    #[account(mut)]
    pub any_unchecked: AccountInfo<'info>, 
}