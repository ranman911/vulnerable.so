use anchor_lang::prelude::*;

#[account]
pub struct Vault {
    pub balance: u64,
    pub owner: Pubkey,
}

declare_id!("7Q7L1Srqz1WY5Avzk1kYyqSCDtnznuaCG2qLBVmczWiN");

#[program]
pub mod unsafe_arithmetic_vuln {
    use super::*;

    pub fn withdraw(ctx: Context<WithdrawVuln>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;

        // --- THE VULNERABILITY ---
        // This line uses the standard subtraction operator (-=).
        //
        // 1. THE BEHAVIOR: 
        //    In Rust, if this code is compiled in "Release" mode (which is standard 
        //    for Solana Mainnet deployments), the compiler does NOT include 
        //    runtime checks for integer underflow. Instead, it uses "Two's Complement" wrapping.
        //
        // 2. THE MATH: 
        //    If vault.balance is 10 and the user requests an amount of 11:
        //    10 - 11 = -1
        //    Since balance is a u64 (unsigned 64-bit integer), it cannot represent -1.
        //    It "wraps around" to the maximum possible value of a u64:
        //    18,446,744,073,709,551,615
        //
        // 3. THE EXPLOIT:
        //    An attacker with a balance of 0 can withdraw 1 Lamport. 
        //    The transaction will succeed, and the attacker's vault balance 
        //    will suddenly become nearly infinite, allowing them to drain 
        //    every other user's funds from the program.
        vault.balance -= amount; 

        Ok(())
    }
}

#[derive(Accounts)]
pub struct WithdrawVuln<'info> {
    // We check that the signer is the owner, but we fail to check 
    // if the owner actually has enough funds for the withdrawal.
    #[account(mut, has_one = owner)]
    pub vault: Account<'info, Vault>,
    pub owner: Signer<'info>,
}

/** 
 * SUMMARY OF ATTACK VECTOR:
 * 1. Attacker creates a Vault and deposits 100 Lamports.
 * 2. Attacker calls `withdraw` with amount = 101.
 * 3. The program calculates 100 - 101.
 * 4. Instead of failing with "Insufficient Funds", the program updates 
 *    the account state to have 18.4 Quintillion units.
 * 5. Attacker now performs a legitimate withdrawal of the entire 
 *    liquidity pool of the protocol.
 */