use anchor_lang::prelude::*;

#[account]
pub struct Vault {
    pub balance: u64,
    pub owner: Pubkey,
}

declare_id!("5LApMfCVxYv3BPjVAkVnnBYnCTsRmRykGGBqBPdZiZsa");

#[program]
pub mod unsafe_arithmetic_fix {
    use super::*;

    pub fn withdraw(ctx: Context<WithdrawSafe>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;

        // --- THE FIX: CHECKED ARITHMETIC ---
        //
        // 1. .checked_sub(amount):
        //    Instead of using the `-` operator, we use a method that returns 
        //    an `Option<u64>`. 
        //    - If the result is >= 0, it returns `Some(result)`.
        //    - If the result would underflow (e.g., 10 - 11), it returns `None`.
        //
        // 2. .ok_or(CustomError::InsufficientFunds):
        //    This converts the `Option` into a `Result`.
        //    - `Some(val)` becomes `Ok(val)`.
        //    - `None` becomes `Err(CustomError::InsufficientFunds)`.
        //
        // 3. The `?` Operator:
        //    If the result is an `Err`, the `?` immediately exits the function 
        //    and returns that error to the Solana runtime.
        //
        // RESULT: The account state is never updated if the math is invalid.
        // The transaction fails, and the attacker gets nothing.
        vault.balance = vault
            .balance
            .checked_sub(amount)
            .ok_or(CustomError::InsufficientFunds)?;

        Ok(())
    }
}

#[derive(Accounts)]
pub struct WithdrawSafe<'info> {
    #[account(mut, has_one = owner)]
    pub vault: Account<'info, Vault>,
    pub owner: Signer<'info>,
}

#[error_code]
pub enum CustomError {
    // Adding a descriptive error message helps frontend developers 
    // and users understand why a transaction was rejected.
    #[msg("The requested withdrawal amount exceeds the vault balance.")]
    InsufficientFunds,
}

/** 
 * WHY THIS IS SECURE:
 * 
 * In the blockchain world, "Atomic Transactions" are key. Because we return 
 * an Error via the `?` operator before the end of the function:
 * 
 * 1. The Solana runtime sees the Error.
 * 2. It discards all changes made to the `vault` account during this call.
 * 3. The attacker's balance remains unchanged.
 * 4. The only thing the attacker loses is the gas fee (SOL) paid to 
 *    execute the failed transaction.
 */