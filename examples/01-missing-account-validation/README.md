# Missing Account Validation

## Table of Contents
1. [Introduction](#introduction)
2. [The Vulnerability Explained](#the-vulnerability-explained)
3. [Understanding AccountInfo vs Account](#understanding-accountinfo-vs-account)
4. [The Attack Scenario](#the-attack-scenario)
5. [Step-by-Step Attack Walkthrough](#step-by-step-attack-walkthrough)
6. [The Fix Explained](#the-fix-explained)
7. [Defense Mechanisms](#defense-mechanisms)
8. [Code Comparison](#code-comparison)
9. [Testing with Pinocchio](#testing-with-pinocchio)
10. [Key Takeaways](#key-takeaways)

## Introduction

Missing account validation is one of the most critical vulnerabilities in Solana smart contract development. Unlike Ethereum, where contracts primarily interact with addresses, Solana programs receive **all account data** from the client. This architectural design means that **the program cannot inherently trust any account passed to it**.

This vulnerability occurs when a program accepts raw `AccountInfo` parameters without validating:
- **Ownership**: Is this account owned by our program?
- **Type**: Is this account the expected data structure?
- **Authority**: Does the signer have permission to modify this account?
- **Identity**: Is this the exact account we expect (via PDA seeds)?

Without these checks, an attacker can substitute legitimate accounts with malicious ones, leading to **account corruption**, **privilege escalation**, or **complete protocol takeover**.

## The Vulnerability Explained

### The Root Cause: Misusing `AccountInfo`

In the vulnerable code (`example1.rs`), the program uses `AccountInfo` directly:

```rust
#[derive(Accounts)]
pub struct SetMessageVuln<'info> {
    #[account(mut)]
    pub any_unchecked: AccountInfo<'info>, 
}
```

**What's wrong here?**

1. **No Ownership Verification**: Anchor doesn't check if `any_unchecked` is owned by this program. An attacker can pass an account owned by the System Program, Token Program, or even another user's protocol.

2. **No Type/Discriminator Validation**: The program has no idea what data structure this account represents. It could be a `MessageBox`, a `TreasuryConfig`, or completely random bytes.

3. **No Authority Check**: Anyone can call this function and pass any account address they want.

4. **Arbitrary Memory Writes**: The program directly manipulates raw bytes:
   ```rust
   let mut data = ctx.accounts.any_unchecked.try_borrow_mut_data()?;
   data[..msg.len()].copy_from_slice(msg.as_bytes());
   ```

### Why This Is Dangerous

On Solana, **clients control which accounts are passed to a program**. The runtime only verifies:
- The account exists
- The transaction was signed correctly
- Writable accounts are marked as `mut`

The runtime **does NOT** verify:
- The account's data type
- The account's owner
- Whether the signer should have access to this account

This is by design—Solana prioritizes performance and flexibility. However, it places the burden of validation entirely on the program developer.

## Understanding AccountInfo vs Account<T>

### AccountInfo (Dangerous)
```rust
pub any_unchecked: AccountInfo<'info>
```
- **Raw account data** with no safety checks
- Anchor performs **zero validation**
- Direct memory access to account bytes
- Used when you need maximum flexibility (rare)
- **Risk**: Complete trust in client-provided data

### Account<'info, T> (Safe)
```rust
pub message_box: Account<'info, MessageBox>
```
- **Type-safe** wrapper around AccountInfo
- Anchor automatically validates:
  - **Discriminator** (8-byte type identifier)
  - **Owner** (must be owned by the program)
  - **Deserialization** (data must match struct)
- **Risk**: Protected against basic substitution attacks

### Additional Constraints (Defense in Depth)
```rust
#[account(
    mut,
    has_one = authority,              // Links to authority field
    seeds = [b"message", authority.key().as_ref()], // PDA validation
    bump
)]
pub message_box: Account<'info, MessageBox>
```
- `has_one`: Validates stored field matches provided account
- `seeds`: Ensures account is derived from expected seeds
- `bump`: Validates canonical PDA bump seed

## The Attack Scenario

### Protocol Setup
Imagine a protocol with two account types:

**MessageBox Account** (intended target):
```rust
pub struct MessageBox {
    pub authority: Pubkey,  // 32 bytes
    pub content: String,    // Variable length
}
```

**TreasuryConfig Account** (valuable target):
```rust
pub struct TreasuryConfig {
    pub admin: Pubkey,      // 32 bytes at offset 8
    pub treasury: Pubkey,   // 32 bytes
    pub fee_bps: u64,       // 8 bytes
}
```

### The Exploit

1. **Attacker Identifies Target**: They find a `TreasuryConfig` account belonging to the protocol at address `Config123...`

2. **Craft Malicious Message**: The attacker creates a message where the first 32 bytes are their own public key: `AttackerKey999...`

3. **Call Vulnerable Function**:
   ```typescript
   await program.methods
     .setMessage("AttackerKey999...{padding}")
     .accounts({
       anyUnchecked: CONFIG_ACCOUNT_ADDRESS, // TreasuryConfig instead of MessageBox!
     })
     .rpc();
   ```

4. **Result**: The program blindly writes to the `TreasuryConfig` account, overwriting the `admin` field with the attacker's public key.

5. **Takeover Complete**: The attacker now controls the protocol's treasury and fee settings.

## Step-by-Step Attack Walkthrough

### Initial State
```
TreasuryConfig Account (Config123...)
├─ Discriminator: [a1, b2, c3, d4, e5, f6, g7, h8]
├─ admin:         [Le...gitAdmin...PublicKey]  ← Legitimate owner
├─ treasury:      [Tr...easury...Address]
└─ fee_bps:       250 (2.5%)
```

### Attack Execution

**Step 1**: Attacker prepares malicious payload
```rust
// Craft 32 bytes of attacker's public key
let malicious_msg = attacker_pubkey.to_string(); // "Att...acker...PublicKey..."
```

**Step 2**: Call vulnerable `set_message` function
```rust
pub fn set_message(ctx: Context<SetMessageVuln>, msg: String) -> Result<()> {
    let mut data = ctx.accounts.any_unchecked.try_borrow_mut_data()?;
    data[..msg.len()].copy_from_slice(msg.as_bytes()); // ← VULNERABILITY
    Ok(())
}
```

**Step 3**: Memory corruption occurs
```
TreasuryConfig Account (Config123...) - AFTER ATTACK
├─ Discriminator: [a1, b2, c3, d4, e5, f6, g7, h8]
├─ admin:         [Att...acker...PublicKey]  ← OVERWRITTEN!
├─ treasury:      [Tr...easury...Address]
└─ fee_bps:       250 (2.5%)
```

**Step 4**: Attacker gains control
```typescript
// Attacker can now call admin-only functions
await protocol.methods
  .withdrawTreasury(allFunds)
  .accounts({
    config: CONFIG_ACCOUNT_ADDRESS,
    admin: attackerWallet.publicKey, // Now matches config.admin!
  })
  .rpc();
```

### Why Traditional Defenses Fail

**"But I check if the account is writable!"**
```rust
#[account(mut)]
pub any_unchecked: AccountInfo<'info>
```
❌ This only ensures the account is marked writable in the transaction. Any writable account can be passed.

**"But I verify the signer!"**
```rust
pub signer: Signer<'info>
```
❌ This only verifies someone signed the transaction, not that they're authorized for this specific account.

**"But I check the account size!"**
```rust
require!(data.len() >= 32, ErrorCode::AccountTooSmall);
```
❌ This doesn't prevent passing the wrong account type with the same size.

## The Fix Explained

The secure version (`programs/01b-missing-account-validation-fix/src/lib.rs`) implements multiple layers of defense:

### Layer 1: Type Safety with Account<T>
```rust
pub message_box: Account<'info, MessageBox>
```

**What Anchor does automatically:**
1. Reads first 8 bytes (discriminator)
2. Compares to `MessageBox::discriminator()`
3. If mismatch → Error: `AccountDiscriminatorMismatch`
4. Checks owner is this program
5. If mismatch → Error: `AccountOwnedByWrongProgram`
6. Deserializes remaining bytes into `MessageBox` struct
7. If fails → Error: `AccountDidNotDeserialize`

### Layer 2: Authority Binding with has_one
```rust
#[account(
    mut,
    has_one = authority  // ← Validates message_box.authority == authority.key()
)]
pub message_box: Account<'info, MessageBox>
pub authority: Signer<'info>
```

**Generated code (conceptual):**
```rust
if message_box.authority != authority.key() {
    return Err(ErrorCode::ConstraintHasOne.into());
}
```

This prevents User A from modifying User B's message box.

### Layer 3: PDA Validation with seeds
```rust
#[account(
    mut,
    has_one = authority,
    seeds = [b"message", authority.key().as_ref()],
    bump
)]
pub message_box: Account<'info, MessageBox>
```

**What this does:**
1. Derives expected PDA address: `Pubkey::find_program_address(&[b"message", authority.key().as_ref()], program_id)`
2. Compares to provided `message_box.key()`
3. If mismatch → Error: `ConstraintSeeds`

**Why this matters:** Even if an attacker creates a fake `MessageBox` account with matching discriminator and authority, the address won't match the expected PDA.

### Layer 4: Input Validation
```rust
require!(msg.len() <= 128, CustomError::MessageTooLong);
```

Prevents:
- Buffer overflows
- Excessive rent costs
- DoS attacks via oversized data

### Layer 5: Type-Safe Field Assignment
```rust
let message_box = &mut ctx.accounts.message_box;
message_box.content = msg; // No raw byte manipulation!
```

Anchor handles serialization/deserialization automatically, preventing:
- Off-by-one errors
- Incorrect offset calculations
- Endianness issues

## Defense Mechanisms

### Defense in Depth Strategy

| Layer | Mechanism | What It Prevents |
|-------|-----------|------------------|
| 1 | `Account<'info, T>` | Wrong account type, wrong owner |
| 2 | `has_one = authority` | Unauthorized access to account |
| 3 | `seeds = [...]` | Substituting valid-looking fake accounts |
| 4 | `require!(...)` | Invalid input data |
| 5 | `Signer<'info>` | Unsigned transactions |

### When to Use Each Constraint

**Use `Account<'info, T>` when:**
- ✅ Account represents a known data structure
- ✅ Account should be owned by your program
- ✅ You need type-safe access to fields

**Use `has_one` when:**
- ✅ Account stores a reference to another account
- ✅ You need to verify relationships between accounts
- ✅ Implementing access control (owner, admin, authority)

**Use `seeds` when:**
- ✅ Account should be a deterministic PDA
- ✅ You want to prevent address spoofing
- ✅ Implementing one-per-user or singleton patterns

**Use `AccountInfo` when:**
- ⚠️ Interfacing with unknown programs (CPI)
- ⚠️ Implementing generic account handlers
- ⚠️ You're absolutely certain you don't need validation
- **Always** add manual validation checks!

## Code Comparison

### Vulnerable Version
```rust
#[derive(Accounts)]
pub struct SetMessageVuln<'info> {
    #[account(mut)]
    pub any_unchecked: AccountInfo<'info>,  // ← NO VALIDATION
}

pub fn set_message(ctx: Context<SetMessageVuln>, msg: String) -> Result<()> {
    let mut data = ctx.accounts.any_unchecked.try_borrow_mut_data()?;
    data[..msg.len()].copy_from_slice(msg.as_bytes()); // ← DANGEROUS
    Ok(())
}
```

**Vulnerabilities:**
- ❌ No owner check
- ❌ No type check
- ❌ No authority check
- ❌ No bounds check
- ❌ Raw memory manipulation

### Secure Version
```rust
#[derive(Accounts)]
pub struct SetMessageSafe<'info> {
    #[account(
        mut,
        has_one = authority,                              // ← Authority check
        seeds = [b"message", authority.key().as_ref()],   // ← Address validation
        bump
    )]
    pub message_box: Account<'info, MessageBox>,          // ← Type + owner check
    pub authority: Signer<'info>,                         // ← Signature check
}

pub fn set_message(ctx: Context<SetMessageSafe>, msg: String) -> Result<()> {
    require!(msg.len() <= 128, CustomError::MessageTooLong); // ← Bounds check
    
    let message_box = &mut ctx.accounts.message_box;
    message_box.content = msg;                            // ← Type-safe assignment
    Ok(())
}
```

**Protections:**
- ✅ Discriminator validation
- ✅ Owner validation
- ✅ Authority binding
- ✅ PDA derivation check
- ✅ Signature verification
- ✅ Input bounds validation
- ✅ Type-safe operations

## Testing with Pinocchio

Pinocchio is a high-performance Solana program testing framework that runs without spinning up a local validator.

### Installation
```bash
# Install Pinocchio
# Pinocchio is included as a workspace dependency

# Or add to your project
pinocchio = { workspace = true }
```

### Running Tests

```bash
# Test the vulnerable version
cd programs/01a-missing-account-validation-vuln
cargo test-sbf

# Test the fixed version
cd programs/01b-missing-account-validation-fix
cargo test-sbf

# Run with verbose output
cargo test-sbf -- --nocapture

# Run specific test
cargo test-sbf test_account_substitution_attack
```

### Example Test Case

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use anchor_lang::prelude::*;
    use pinocchio_test::*;

    #[test]
    fn test_account_substitution_attack() {
        // Setup
        let mut context = ProgramTest::default();
        let attacker = Keypair::new();
        
        // Create a TreasuryConfig account
        let treasury_config = create_account(
            &mut context,
            &TreasuryConfig {
                admin: legitimate_admin.pubkey(),
                treasury: treasury.pubkey(),
                fee_bps: 250,
            }
        );
        
        // ATTACK: Try to pass TreasuryConfig to set_message
        let result = set_message(
            &mut context,
            SetMessageVuln {
                any_unchecked: treasury_config, // Wrong account type!
            },
            attacker.pubkey().to_string()
        );
        
        // Vulnerable version: SUCCEEDS (bad!)
        // Fixed version: FAILS with AccountDiscriminatorMismatch (good!)
        assert!(result.is_err());
    }
}
```

### Expected Outputs

**Vulnerable Version:**
```
test test_account_substitution_attack ... ok
⚠️  Account was corrupted! Treasury admin overwritten.
```

**Fixed Version:**
```
test test_account_substitution_attack ... FAILED
Error: AccountDiscriminatorMismatch
✅ Attack prevented by type validation
```

## Key Takeaways

### For Developers

1. **Never use raw `AccountInfo` for program-owned accounts** unless you have a specific reason and implement manual validation.

2. **Always use `Account<'info, T>`** for typed accounts owned by your program.

3. **Layer your defenses**: Type safety + authority binding + PDA validation.

4. **Validate all inputs**: Check lengths, ranges, and business logic constraints.

5. **Test attack scenarios**: Write tests that attempt to pass wrong accounts, unauthorized signers, and invalid data.

### For Auditors

1. **Search for `AccountInfo` usage**: Any `AccountInfo` parameter is a red flag requiring scrutiny.

2. **Verify account constraints**: Ensure `has_one`, `seeds`, and other constraints are properly applied.

3. **Check for manual validation**: If `AccountInfo` is used, verify explicit owner, discriminator, and authority checks.

4. **Test account substitution**: Attempt to pass different account types to each instruction.

### Common Pitfalls

❌ **Pitfall 1**: "I'll just check the account size"
```rust
require!(data.len() == 100, ErrorCode::InvalidAccountSize);
```
**Why it fails**: Multiple account types can have the same size.

❌ **Pitfall 2**: "I'll verify the owner manually"
```rust
require!(account.owner == program_id, ErrorCode::WrongOwner);
```
**Why it fails**: Doesn't check discriminator or authority.

❌ **Pitfall 3**: "I'll use UncheckedAccount with a comment"
```rust
/// CHECK: This is safe because reasons
pub unchecked: UncheckedAccount<'info>
```
**Why it fails**: Comments don't execute. You still need runtime checks.

✅ **Solution**: Use `Account<'info, T>` with appropriate constraints.

## Further Reading

- [Solana Account Model](https://docs.solana.com/developing/programming-model/accounts) - Understanding Solana's account architecture
- [Anchor Account Constraints](https://www.anchor-lang.com/docs/attributes) - Complete guide to `seeds`, `has_one`, `owner`
- [Anchor Security Best Practices](https://www.anchor-lang.com/docs/security) - Official security guidelines
- [Pinocchio Testing Framework](https://github.com/anza-xyz/pinocchio) - Fast local testing without validators
- [Neodyme Security Blog](https://blog.neodyme.io/) - Real-world Solana vulnerability analyses

## License

This example is part of the Solana Security Examples repository and is provided for educational purposes.
