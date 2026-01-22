# Incorrect Authority Check

## Table of Contents
1. [Introduction](#introduction)
2. [Authentication vs Authorization](#authentication-vs-authorization)
3. [The Vulnerability Explained](#the-vulnerability-explained)
4. [Understanding the Signer Type](#understanding-the-signer-type)
5. [The Exploit Scenario](#the-exploit-scenario)
6. [Attack Anatomy](#attack-anatomy)
7. [The Fix: has_one Constraint](#the-fix-has_one-constraint)
8. [Best Practices for Authority Checks](#best-practices-for-authority-checks)
9. [Code Comparison](#code-comparison)
10. [Testing with Pinocchio](#testing-with-pinocchio)
11. [Key Takeaways](#key-takeaways)

## Introduction

Incorrect authority checks represent one of the most common and dangerous vulnerabilities in Solana programs. This vulnerability occurs when a program verifies that **someone** signed a transaction (authentication) but fails to verify that this signer is **authorized** to perform the requested action (authorization).

In traditional web development, you might think of this as the difference between:
- **Authentication**: "You are logged in as user123" ✅
- **Authorization**: "User123 is an admin who can modify system settings" ❌

Many developers mistakenly believe that using the `Signer` type in Anchor is sufficient for access control. However, **`Signer` only proves a signature exists—it doesn't prove the signer has permission**.

This vulnerability can lead to:
- Unauthorized protocol parameter changes
- Fee manipulation
- Privilege escalation
- Complete protocol takeover

## Authentication vs Authorization

### Authentication: "Who are you?"
```rust
pub caller: Signer<'info>
```
**What Anchor verifies:**
- ✅ This account signed the transaction
- ✅ The signature is cryptographically valid

**What Anchor DOES NOT verify:**
- ❌ This signer is the protocol admin
- ❌ This signer owns the account being modified
- ❌ This signer has permission for this action

### Authorization: "Are you allowed to do this?"
```rust
#[account(
    mut,
    has_one = admin  // ← This is authorization!
)]
pub config: Account<'info, Config>,
pub admin: Signer<'info>
```
**What Anchor verifies:**
- ✅ The transaction is signed
- ✅ The signer's public key matches `config.admin`
- ✅ Only the stored admin can modify this config

### The Critical Distinction

**Authentication alone is insufficient:**
```rust
// ❌ VULNERABLE: Any signer can call this
pub fn dangerous_action(ctx: Context<DangerousAccounts>) -> Result<()> {
    // If we reach here, someone signed the transaction
    // But we don't know if they're authorized!
    ctx.accounts.config.critical_value = new_value;
    Ok(())
}

#[derive(Accounts)]
pub struct DangerousAccounts<'info> {
    #[account(mut)]
    pub config: Account<'info, Config>,
    pub caller: Signer<'info>,  // ← Just proves *someone* signed
}
```

**Authorization makes it secure:**
```rust
// ✅ SECURE: Only the admin can call this
pub fn safe_action(ctx: Context<SafeAccounts>) -> Result<()> {
    // If we reach here, the admin signed the transaction
    ctx.accounts.config.critical_value = new_value;
    Ok(())
}

#[derive(Accounts)]
pub struct SafeAccounts<'info> {
    #[account(
        mut,
        has_one = admin  // ← Proves the admin signed
    )]
    pub config: Account<'info, Config>,
    pub admin: Signer<'info>,
}
```

## The Vulnerability Explained

### Vulnerable Code Analysis

Let's examine the vulnerable code from `example2.rs`:

```rust
#[program]
pub mod incorrect_authority_vuln {
    use super::*;

    pub fn set_fee(ctx: Context<SetFeeVuln>, new_fee: u16) -> Result<()> {
        let config = &mut ctx.accounts.config;
        
        // CRITICAL BUG: No check that caller == config.admin
        config.fee_bps = new_fee;
        
        msg!("Fee updated to: {}", new_fee);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct SetFeeVuln<'info> {
    #[account(mut)]
    pub config: Account<'info, Config>,
    
    pub caller: Signer<'info>,  // ← Only proves signature exists
}

#[account]
pub struct Config {
    pub admin: Pubkey,   // ← STORED BUT NEVER CHECKED!
    pub fee_bps: u16,
}
```

### What's Wrong?

1. **The `admin` field exists** in the `Config` struct
2. **The `caller` must sign** the transaction
3. **But nowhere does the program verify** that `caller.key() == config.admin`

### Why Developers Make This Mistake

**Assumption**: "If I require a `Signer`, only the admin can call this function."

**Reality**: Any Solana account can sign a transaction. The attacker simply uses their own wallet:

```typescript
// Attacker's malicious transaction
const attackerWallet = Keypair.generate();

await program.methods
  .setFee(9999)  // Set fee to 99.99%!
  .accounts({
    config: CONFIG_ACCOUNT_ADDRESS,
    caller: attackerWallet.publicKey,  // Attacker's own wallet
  })
  .signers([attackerWallet])  // Attacker signs with their own key
  .rpc();

// ✅ Transaction succeeds because:
// 1. attackerWallet is a valid signer
// 2. Program never checks if attackerWallet == config.admin
```

## Understanding the Signer Type

### What `Signer` Does
```rust
pub caller: Signer<'info>
```

**Anchor's validation:**
```rust
// Conceptual code Anchor generates
if !account_info.is_signer {
    return Err(ErrorCode::AccountNotSigner.into());
}
```

**That's it.** Anchor only checks that the account signed the transaction. It doesn't care **who** signed it.

### What `Signer` Doesn't Do

❌ Doesn't check if the signer is the admin  
❌ Doesn't check if the signer owns the account  
❌ Doesn't check if the signer has permission  
❌ Doesn't compare the signer to any stored value  

### Common Misconceptions

**Myth 1**: "Using `Signer` restricts access to authorized users"
- **Reality**: Any account can be a signer

**Myth 2**: "The program knows who the admin is from the `Config` account"
- **Reality**: The program must explicitly verify the caller matches the stored admin

**Myth 3**: "Anchor automatically enforces authorization"
- **Reality**: You must use constraints like `has_one` for authorization

## The Exploit Scenario

### Protocol Setup

Consider a DeFi protocol with fee collection:

```rust
#[account]
pub struct Config {
    pub admin: Pubkey,    // Protocol deployer
    pub fee_bps: u16,     // Fee in basis points (1 bps = 0.01%)
}

// Normal fee: 250 bps = 2.5%
// Max reasonable fee: 1000 bps = 10%
```

### Attack Execution

**Step 1: Reconnaissance**
```bash
# Attacker finds the config account
$ solana account Config111...
Owner: YourProtocol111...
Data:
  admin: LegitAdmin111...
  fee_bps: 250
```

**Step 2: Craft Malicious Transaction**
```typescript
const attacker = Keypair.generate();

// Attacker sets fee to 100% (steal all trades)
const tx = await program.methods
  .setFee(10000)  // 10,000 bps = 100%
  .accounts({
    config: configAccount,
    caller: attacker.publicKey,  // Attacker's wallet
  })
  .signers([attacker])
  .rpc();

console.log("✅ Fee changed to 100%!");
```

**Step 3: Profit**
```typescript
// Next user makes a $10,000 trade
// Expected fee: 2.5% = $250
// Actual fee: 100% = $10,000
// Attacker steals: $9,750
```

### Real-World Impact

**If successful, the attacker can:**
1. Set fees to 100% (steal all transaction value)
2. Set fees to 0% (drain protocol revenue)
3. Front-run protocol upgrades
4. Modify other critical parameters (if similar bugs exist)

**Historical examples:**
- Wormhole Bridge: $320M (partially due to authorization issues)
- Cashio: $52M (mint authority not properly checked)
- Crema Finance: $8.8M (authorization logic flaw)

## Attack Anatomy

### Phase 1: Discovery
```bash
# Attacker scans for vulnerable programs
$ pinocchio analyze --vulnerability auth-check

Found vulnerability in program: YourProtocol111...
  Function: set_fee
  Issue: Signer not validated against stored admin
  Risk: CRITICAL
```

### Phase 2: Exploitation Script
```typescript
import { Connection, Keypair, PublicKey } from '@solana/web3.js';
import { AnchorProvider, Program } from '@coral-xyz/anchor';

async function exploit() {
  // Generate attacker wallet
  const attacker = Keypair.generate();
  
  // Fund attacker wallet (minimal SOL for transaction fees)
  await connection.requestAirdrop(attacker.publicKey, 0.1 * LAMPORTS_PER_SOL);
  
  // Load vulnerable program
  const program = new Program(idl, programId, provider);
  
  // Find config account (on-chain data is public)
  const [configAccount] = PublicKey.findProgramAddressSync(
    [Buffer.from("config")],
    programId
  );
  
  // Malicious transaction
  try {
    await program.methods
      .setFee(10000)  // 100% fee
      .accounts({
        config: configAccount,
        caller: attacker.publicKey,
      })
      .signers([attacker])
      .rpc();
    
    console.log("💰 Exploit successful! Fee set to 100%");
  } catch (err) {
    console.log("❌ Exploit failed (program might be secure)");
  }
}
```

### Phase 3: Monitoring
```typescript
// Attacker monitors for fee collection
program.addEventListener("FeeCollected", (event) => {
  console.log(`Collected ${event.amount} from victim`);
});
```

## The Fix: has_one Constraint

### Secure Implementation

The fixed code (`example2.fix.rs`) adds the critical `has_one` constraint:

```rust
#[derive(Accounts)]
pub struct SetFeeSafe<'info> {
    #[account(
        mut,
        has_one = admin @ CustomError::Unauthorized  // ← THE FIX
    )]
    pub config: Account<'info, Config>,
    
    pub admin: Signer<'info>,  // ← Must match config.admin
}
```

### How `has_one` Works

**Code Anchor generates (conceptual):**
```rust
// Before your instruction handler runs
if ctx.accounts.config.admin != ctx.accounts.admin.key() {
    return Err(CustomError::Unauthorized.into());
}
```

**Step-by-step validation:**
1. Anchor deserializes the `config` account
2. Reads the `admin` field from account data
3. Compares it to `admin.key()` (the provided account)
4. If they don't match → Transaction fails immediately
5. If they match → Your instruction handler runs

### Custom Error Messages

```rust
#[account(
    mut,
    has_one = admin @ CustomError::Unauthorized  // ← Custom error
)]
```

**Without custom error:**
```
Error: ConstraintHasOne (Anchor's generic error)
```

**With custom error:**
```
Error: The provided admin does not match the config admin.
```

Custom errors improve:
- **Developer experience**: Easier debugging
- **User experience**: Clear error messages
- **Security**: Helps identify attack attempts in logs

## Best Practices for Authority Checks

### 1. Always Use `has_one` for Admin/Owner Checks
```rust
✅ CORRECT
#[account(mut, has_one = admin)]
pub config: Account<'info, Config>,
pub admin: Signer<'info>

❌ INCORRECT
#[account(mut)]
pub config: Account<'info, Config>,
pub admin: Signer<'info>
```

### 2. Add Logical Validation
```rust
pub fn set_fee(ctx: Context<SetFeeSafe>, new_fee: u16) -> Result<()> {
    // Authorization is verified by has_one
    // But still validate business logic!
    require!(new_fee <= 10_000, CustomError::InvalidFee);
    
    ctx.accounts.config.fee_bps = new_fee;
    Ok(())
}
```

### 3. Use Descriptive Error Messages
```rust
#[error_code]
pub enum CustomError {
    #[msg("The provided admin does not match the config admin.")]
    Unauthorized,
    
    #[msg("The fee must be between 0 and 10,000 basis points (100%).")]
    InvalidFee,
}
```

### 4. Consider Multiple Authority Levels
```rust
#[account]
pub struct Config {
    pub super_admin: Pubkey,  // Can do everything
    pub admin: Pubkey,        // Can change fees
    pub operator: Pubkey,     // Can pause/unpause
}

// Different functions for different roles
#[account(mut, has_one = super_admin)]  // Critical actions
#[account(mut, has_one = admin)]        // Admin actions
#[account(mut, has_one = operator)]     // Operator actions
```

### 5. Validate Before State Changes
```rust
pub fn set_fee(ctx: Context<SetFeeSafe>, new_fee: u16) -> Result<()> {
    // 1. All validation first (has_one + require!)
    require!(new_fee <= 10_000, CustomError::InvalidFee);
    
    // 2. State changes after validation
    ctx.accounts.config.fee_bps = new_fee;
    
    // 3. Events/logging last
    emit!(FeeChanged {
        old_fee: ctx.accounts.config.fee_bps,
        new_fee,
    });
    
    Ok(())
}
```

### 6. Manual Checks as Fallback
```rust
// If you can't use has_one for some reason, check manually
pub fn complex_authorization(ctx: Context<ComplexAuth>) -> Result<()> {
    let config = &ctx.accounts.config;
    let caller = &ctx.accounts.caller;
    
    // Manual check
    require_keys_eq!(
        config.admin,
        caller.key(),
        CustomError::Unauthorized
    );
    
    // Or multiple possible admins
    require!(
        config.admin == caller.key() || config.super_admin == caller.key(),
        CustomError::Unauthorized
    );
    
    Ok(())
}
```

## Code Comparison

### Vulnerable Version
```rust
// ❌ VULNERABLE CODE
#[program]
pub mod incorrect_authority_vuln {
    use super::*;

    pub fn set_fee(ctx: Context<SetFeeVuln>, new_fee: u16) -> Result<()> {
        let config = &mut ctx.accounts.config;
        config.fee_bps = new_fee;  // ← Anyone can reach this!
        Ok(())
    }
}

#[derive(Accounts)]
pub struct SetFeeVuln<'info> {
    #[account(mut)]
    pub config: Account<'info, Config>,
    pub caller: Signer<'info>,  // ← Only checks signature
}
```

**Vulnerabilities:**
- ❌ No authorization check
- ❌ No input validation
- ❌ No error handling
- ❌ Any signer can modify fees

**Attack vector:**
```typescript
// Any wallet can call this
await program.methods
  .setFee(10000)
  .accounts({
    config: configAccount,
    caller: anyRandomWallet.publicKey,  // ← Attacker
  })
  .signers([anyRandomWallet])
  .rpc();
```

### Secure Version
```rust
// ✅ SECURE CODE
#[program]
pub mod incorrect_authority_fix {
    use super::*;

    pub fn set_fee(ctx: Context<SetFeeSafe>, new_fee: u16) -> Result<()> {
        // Input validation
        require!(new_fee <= 10_000, CustomError::InvalidFee);

        // State update (only reachable if admin signed)
        ctx.accounts.config.fee_bps = new_fee;
        
        msg!("Fee successfully updated to: {}", new_fee);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct SetFeeSafe<'info> {
    #[account(
        mut,
        has_one = admin @ CustomError::Unauthorized  // ← Authorization
    )]
    pub config: Account<'info, Config>,
    pub admin: Signer<'info>,  // ← Must be the stored admin
}

#[error_code]
pub enum CustomError {
    #[msg("The provided admin does not match the config admin.")]
    Unauthorized,
    #[msg("The fee must be between 0 and 10,000 basis points (100%).")]
    InvalidFee,
}
```

**Protections:**
- ✅ `has_one = admin` enforces authorization
- ✅ Input validation (0-10,000 bps)
- ✅ Custom error messages
- ✅ Only the stored admin can modify fees

**Attack attempt:**
```typescript
// Attacker tries to call with their wallet
await program.methods
  .setFee(10000)
  .accounts({
    config: configAccount,
    caller: attackerWallet.publicKey,  // ← Not the admin
  })
  .signers([attackerWallet])
  .rpc();

// ❌ Transaction fails:
// Error: The provided admin does not match the config admin.
```

## Testing with Pinocchio

### Installation
```bash
# Install Pinocchio
# Pinocchio is included as a workspace dependency

# Or add to your project
pinocchio = { workspace = true }
```

### Test Cases

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use pinocchio_test::*;

    #[test]
    fn test_unauthorized_fee_change() {
        let mut context = ProgramTest::default();
        
        // Setup
        let admin = Keypair::new();
        let attacker = Keypair::new();
        
        let config = create_account(
            &mut context,
            &Config {
                admin: admin.pubkey(),
                fee_bps: 250,
            }
        );
        
        // ATTACK: Attacker tries to change fee
        let result = set_fee(
            &mut context,
            SetFeeVuln {
                config,
                caller: attacker.pubkey(),  // ← Attacker, not admin
            },
            10000  // 100% fee
        );
        
        // Vulnerable version: SUCCEEDS (bad!)
        // Fixed version: FAILS with Unauthorized (good!)
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            ProgramError::Custom(CustomError::Unauthorized as u32)
        );
    }

    #[test]
    fn test_admin_can_change_fee() {
        let mut context = ProgramTest::default();
        
        let admin = Keypair::new();
        let config = create_account(
            &mut context,
            &Config {
                admin: admin.pubkey(),
                fee_bps: 250,
            }
        );
        
        // Legitimate admin change
        let result = set_fee(
            &mut context,
            SetFeeSafe {
                config,
                admin: admin.pubkey(),  // ← Correct admin
            },
            500
        );
        
        assert!(result.is_ok());
        
        // Verify fee changed
        let config_data = get_account::<Config>(&context, config);
        assert_eq!(config_data.fee_bps, 500);
    }

    #[test]
    fn test_invalid_fee_rejected() {
        let mut context = ProgramTest::default();
        
        let admin = Keypair::new();
        let config = create_account(
            &mut context,
            &Config {
                admin: admin.pubkey(),
                fee_bps: 250,
            }
        );
        
        // Try to set invalid fee (over 100%)
        let result = set_fee(
            &mut context,
            SetFeeSafe {
                config,
                admin: admin.pubkey(),
            },
            20000  // 200% - invalid!
        );
        
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            ProgramError::Custom(CustomError::InvalidFee as u32)
        );
    }
}
```

### Running Tests

```bash
# Test vulnerable version (should fail security tests)
cd programs/02a-incorrect-authority-check-vuln
cargo test-sbf

# Test fixed version (should pass all tests)
cd programs/02b-incorrect-authority-check-fix
cargo test-sbf

# Run with verbose output
cargo test-sbf -- --nocapture --test-threads=1

# Run specific test
cargo test-sbf test_unauthorized_fee_change
```

### Expected Outputs

**Vulnerable Version:**
```
running 3 tests
test test_unauthorized_fee_change ... FAILED
  expected: transaction should fail
  actual: transaction succeeded
  ⚠️  Security issue: Unauthorized user changed fee!

test test_admin_can_change_fee ... ok
test test_invalid_fee_rejected ... FAILED
  expected: invalid fee rejected
  actual: accepted fee of 20000 bps (200%)
```

**Fixed Version:**
```
running 3 tests
test test_unauthorized_fee_change ... ok
  ✅ Unauthorized access correctly blocked
  Error: The provided admin does not match the config admin.

test test_admin_can_change_fee ... ok
  ✅ Legitimate admin can update fee

test test_invalid_fee_rejected ... ok
  ✅ Invalid fee correctly rejected
  Error: The fee must be between 0 and 10,000 basis points.
```

## Key Takeaways

### For Developers

1. **`Signer` ≠ Authorization**: The `Signer` type only proves a signature exists, not that the signer has permission.

2. **Always use `has_one`** for admin/owner checks when the authority is stored in an account.

3. **Layer your security**:
   - Authorization: `has_one = admin`
   - Input validation: `require!(value <= max, Error::Invalid)`
   - Business logic: Check state before modification

4. **Test unauthorized access**: Every privileged function should have a test attempting unauthorized access.

5. **Use custom errors**: Help users and developers understand why a transaction failed.

### For Auditors

1. **Look for `Signer` without `has_one`**: Any privileged function using `Signer` without authority binding is suspicious.

2. **Verify account constraints**: Check that all authority fields are validated.

3. **Test with unauthorized signers**: Attempt to call privileged functions with random wallets.

4. **Check for manual validation**: If `has_one` isn't used, verify explicit `require_keys_eq!` checks exist.

### Common Patterns

✅ **Secure pattern:**
```rust
#[account(mut, has_one = admin)]
pub config: Account<'info, Config>,
pub admin: Signer<'info>
```

✅ **Also secure (manual check):**
```rust
require_keys_eq!(
    ctx.accounts.config.admin,
    ctx.accounts.caller.key(),
    ErrorCode::Unauthorized
);
```

❌ **Insecure pattern:**
```rust
#[account(mut)]
pub config: Account<'info, Config>,
pub caller: Signer<'info>  // ← No authority check!
```

## Further Reading

- [Anchor `has_one` Documentation](https://www.anchor-lang.com/docs/attributes#has_one) - Official constraint documentation
- [Solana Signers](https://docs.solana.com/developing/programming-model/accounts#signers) - Understanding signatures on Solana
- [Anchor Security Guidelines](https://www.anchor-lang.com/docs/security) - Official security best practices
- [Pinocchio Testing](https://github.com/anza-xyz/pinocchio) - Fast local testing framework
- [Neodyme Blog](https://blog.neodyme.io/) - Real-world security analyses

## License

This example is part of the Solana Security Examples repository and is provided for educational purposes.
