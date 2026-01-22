use anchor_lang::prelude::*;

#[account]
pub struct MessageBox {
    pub authority: Pubkey,
    pub content: String,
}

declare_id!("HxhZNeWzpPkhZFBQC7KVio9oi5v4SjFFBXd5pTKmNsmV");

#[program]
pub mod missing_account_fix {
    use super::*;

    pub fn set_message(ctx: Context<SetMessageSafe>, msg: String) -> Result<()> {
        // --- STEP 1: LOGICAL BOUNDS CHECKING ---
        // Instead of blindly copying slices (which can crash the program), 
        // we enforce a business-logic limit. This prevents account data 
        // from being cluttered or corrupted by unexpectedly large inputs.
        require!(msg.len() <= 128, CustomError::MessageTooLong);

        // --- STEP 2: TYPE-SAFE FIELD ASSIGNMENT ---
        // Because 'message_box' is now a typed 'Account<MessageBox>', we don't 
        // touch raw bytes. We update the 'content' field directly. 
        // Anchor handles the serialization (turning this back into bytes) 
        // safely and automatically behind the scenes.
        let message_box = &mut ctx.accounts.message_box;
        message_box.content = msg;
        
        Ok(())
    }
}

#[derive(Accounts)]
pub struct SetMessageSafe<'info> {
    // --- STEP 3: AUTOMATIC TYPE & OWNER VALIDATION ---
    // Using 'Account<'info, MessageBox>' instead of 'AccountInfo' triggers two checks:
    // 1. Discriminator Check: Anchor verifies the first 8 bytes of the account match 
    //    the 'MessageBox' type. (Fixes "Type/Discriminator Confusion")
    // 2. Owner Check: Anchor verifies the account is owned by this program.
    //    (Fixes "Ownership Verification" bug)
    #[account(
        mut,
        // --- STEP 4: AUTHORIZATION (has_one) ---
        // This ensures the 'authority' field stored INSIDE the MessageBox account 
        // matches the 'authority' account passed in this transaction.
        // This prevents User A from trying to modify User B's message box.
        has_one = authority,

        // --- STEP 5: ADDRESS IDENTITY (Seeds & Bumps) ---
        // This enforces that the 'message_box' account MUST be a PDA derived from 
        // the string "message" and the authority's public key.
        // BUG FIXED: An attacker cannot pass a "TreasuryConfig" account here 
        // because its address wouldn't match these seeds.
        seeds = [b"message", authority.key().as_ref()],
        bump
    )]
    pub message_box: Account<'info, MessageBox>,

    // --- STEP 6: CRYPTOGRAPHIC SIGNATURE CHECK ---
    // By typing this as 'Signer', Anchor automatically verifies that the 
    // transaction was signed by the private key of this account.
    // (Fixes "Lack of Signer Validation" bug)
    pub authority: Signer<'info>,
}

#[error_code]
pub enum CustomError {
    #[msg("message too long")]
    MessageTooLong,
}
