# Unsafe Arithmetic

## Table of Contents
1. [Introduction](#introduction)
2. [Understanding Integer Overflow and Underflow](#understanding-integer-overflow-and-underflow)
3. [Release vs Debug Mode Behavior](#release-vs-debug-mode-behavior)
4. [The Math Behind Wrapping Arithmetic](#the-math-behind-wrapping-arithmetic)
5. [The Vulnerability Explained](#the-vulnerability-explained)
6. [Attack Scenario: Infinite Balance](#attack-scenario-infinite-balance)
7. [Checked Arithmetic Methods](#checked-arithmetic-methods)
8. [Proper Error Handling](#proper-error-handling)
9. [Code Comparison](#code-comparison)
10. [Testing with Pinocchio](#testing-with-pinocchio)
11. [Key Takeaways](#key-takeaways)

## Introduction

Unsafe arithmetic is a critical vulnerability class that has led to some of the most devastating exploits in blockchain history. On Solana, where programs are compiled in **release mode** (optimized for performance), integer overflow and underflow do not panic—they **silently wrap around**, potentially giving attackers astronomical balances or bypassing critical checks.

This vulnerability occurs when arithmetic operations on unsigned integers produce results outside their valid range:
- **Underflow**: `0 - 1` for unsigned integers wraps to maximum value
- **Overflow**: `u64::MAX + 1` wraps to 0

In traditional software, this might cause a crash. In blockchain smart contracts, this can mean:
- Infinite token balances
- Bypassed authorization checks
- Complete fund drainage
- Protocol insolvency

**Historical impact:**
- DAO Hack (Ethereum): $60M (reentrancy + arithmetic)
- BNB Chain Bridge: $566M (underflow in proof verification)
- Poly Network: $611M (privilege bypass via overflow)

## Understanding Integer Overflow and Underflow

### Integer Representation

Unsigned integers (u8, u16, u32, u64, u128) can only represent **non-negative** values:

```
u8:   0 to 255
u16:  0 to 65,535
u32:  0 to 4,294,967,295
u64:  0 to 18,446,744,073,709,551,615
u128: 0 to 340,282,366,920,938,463,463,374,607,431,768,211,455
```

### Underflow: Going Below Zero

**Example with u8 (0-255):**
```rust
let balance: u8 = 10;
let withdrawal: u8 = 11;

// What happens?
let result = balance - withdrawal;  // In release mode: wraps to 255!
```

**Why this happens (Two's Complement):**
```
  10 in binary: 0000_1010
- 11 in binary: 0000_1011
--------------------------
Borrow occurs, result wraps:
Result:         1111_1111  = 255
```

### Overflow: Going Above Maximum

**Example with u8:**
```rust
let balance: u8 = 255;
let deposit: u8 = 1;

let result = balance + deposit;  // In release mode: wraps to 0!
```

**Binary representation:**
```
  255 in binary: 1111_1111
+   1 in binary: 0000_0001
--------------------------
Carry lost (8 bits):
Result:          0000_0000  = 0
```

### In Solana's Context (u64)

Most Solana programs use `u64` for balances (lamports, tokens):

```rust
// Vulnerable code
let balance: u64 = 100_000_000;  // 0.1 SOL
let withdrawal: u64 = 100_000_001;  // 0.100000001 SOL

balance -= withdrawal;  
// Result: 18,446,744,073,709,551,714 lamports
//       = 18,446,744,073.709551714 SOL
//       = $18+ billion at $1000/SOL
```

## Release vs Debug Mode Behavior

### Debug Mode (Development)
```bash
$ cargo build
$ cargo test
```

**Behavior:**
- Overflow/underflow **panics** at runtime
- Program crashes with helpful error message
- Helps developers catch bugs during testing

**Example:**
```rust
#[test]
fn test_underflow() {
    let balance: u64 = 10;
    let withdrawal: u64 = 11;
    
    let result = balance - withdrawal;  
    // ❌ PANIC: attempt to subtract with overflow
}
```

### Release Mode (Production)
```bash
$ cargo build-sbf  # Solana programs
$ cargo build --release
```

**Behavior:**
- Overflow/underflow **wraps silently**
- No panic, no error, no indication
- Continues execution with wrapped value
- **This is the default on Solana mainnet**

**Example:**
```rust
fn withdraw(balance: u64, amount: u64) -> u64 {
    balance - amount  
    // If amount > balance:
    //   Debug: PANIC
    //   Release: WRAPS to huge number
}
```

### Why Solana Uses Release Mode

1. **Performance**: Overflow checks add CPU overhead
2. **Determinism**: Consistent behavior across validators
3. **Predictability**: No random panics during execution
4. **Cost**: Lower compute units = cheaper transactions

**The trade-off:** Developers must manually handle arithmetic safety.

## The Math Behind Wrapping Arithmetic

### Two's Complement Representation

Computers use two's complement for signed integers. When applied to unsigned integers, it causes wrapping:

**Example: u8 underflow**
```
Desired: 10 - 11 = -1
But u8 can't represent -1, so it wraps:

Step 1: Convert to two's complement
  10 = 0000_1010
 -11 = 1111_0101 (two's complement of 11)

Step 2: Add (subtraction is addition of negative)
  0000_1010
+ 1111_0101
-----------
  1111_1111 = 255 (ignoring overflow bit)
```

### Modular Arithmetic

Wrapping follows modular arithmetic:
```
(a - b) mod 2^n where n = bit width

For u64:
(10 - 11) mod 2^64 = 18,446,744,073,709,551,615
```

### Practical Example: Vault Balance

```rust
#[account]
pub struct Vault {
    pub balance: u64,  // In lamports (1 SOL = 1_000_000_000 lamports)
    pub owner: Pubkey,
}

// User has 0.1 SOL = 100_000_000 lamports
vault.balance = 100_000_000;

// User tries to withdraw 0.2 SOL = 200_000_000 lamports
vault.balance -= 200_000_000;

// Result:
// 100_000_000 - 200_000_000 
// = -100_000_000 (in math)
// = 18,446,744,073,609,551,615 (in u64)
// = 18,446,744,073.609551615 SOL
```

**Exploitation:**
```rust
// Attacker now withdraws this astronomical balance
// If the program has 1000 SOL total, attacker drains it all
// If the program has less, transaction fails with "insufficient lamports"
// But attacker can withdraw up to the program's entire balance
```

## The Vulnerability Explained

### Vulnerable Code Analysis

From `example3.rs`:

```rust
#[program]
pub mod unsafe_arithmetic_vuln {
    use super::*;

    pub fn withdraw(ctx: Context<WithdrawVuln>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;

        // ❌ CRITICAL VULNERABILITY
        vault.balance -= amount;  
        // If amount > vault.balance:
        //   Expected: Error
        //   Actual: Wraps to huge number

        Ok(())
    }
}

#[derive(Accounts)]
pub struct WithdrawVuln<'info> {
    #[account(mut, has_one = owner)]
    pub vault: Account<'info, Vault>,
    pub owner: Signer<'info>,  // ✅ Owner is verified
}                              // ❌ But balance isn't checked
```

### What's Missing?

1. **No balance check**: Program doesn't verify `amount <= vault.balance`
2. **Uses `-=` operator**: In release mode, this wraps on underflow
3. **No error handling**: Function returns `Ok(())` even after wrapping

### The Attack Vector

```rust
// Setup: Attacker creates a vault with 1 lamport
create_vault(attacker, initial_balance: 1);

// Attack: Withdraw 2 lamports (more than balance)
withdraw(attacker_vault, amount: 2);

// Result:
// Before: balance = 1
// After:  balance = 1 - 2 = 18,446,744,073,709,551,615

// Attacker can now withdraw entire protocol treasury
withdraw(attacker_vault, amount: protocol_total_balance);
```

## Attack Scenario: Infinite Balance

### Phase 1: Setup

**Attacker deploys exploit:**
```typescript
import { Connection, Keypair, LAMPORTS_PER_SOL } from '@solana/web3.js';
import { AnchorProvider, Program } from '@coral-xyz/anchor';

async function exploit() {
  const attacker = Keypair.generate();
  const connection = new Connection('https://api.mainnet-beta.solana.com');
  
  // Fund attacker with minimal SOL
  await connection.requestAirdrop(
    attacker.publicKey, 
    0.1 * LAMPORTS_PER_SOL
  );
  
  // Create vault with 1 lamport
  const vault = await createVault(attacker, 1);
  console.log(`Initial balance: ${vault.balance} lamports`);
}
```

### Phase 2: Trigger Underflow

```typescript
// Withdraw more than balance
const tx = await program.methods
  .withdraw(new BN(2))  // Withdraw 2 lamports
  .accounts({
    vault: vaultAccount,
    owner: attacker.publicKey,
  })
  .signers([attacker])
  .rpc();

console.log(`Transaction: ${tx}`);

// Check new balance
const vaultData = await program.account.vault.fetch(vaultAccount);
console.log(`New balance: ${vaultData.balance} lamports`);
// Output: New balance: 18446744073709551615 lamports
```

### Phase 3: Drain Protocol

```typescript
// Find protocol's total balance
const protocolBalance = await connection.getBalance(programAddress);
console.log(`Protocol has: ${protocolBalance} lamports`);

// Withdraw entire protocol balance
await program.methods
  .withdraw(new BN(protocolBalance))
  .accounts({
    vault: vaultAccount,
    owner: attacker.publicKey,
    recipient: attackerWallet.publicKey,
  })
  .signers([attacker])
  .rpc();

console.log(`💰 Drained ${protocolBalance / LAMPORTS_PER_SOL} SOL`);
```

### Real-World Scenario

**DeFi Protocol:**
```
Total Value Locked: 10,000 SOL ($10M at $1000/SOL)
Minimum deposit: 0.01 SOL

Attack cost: 0.01 SOL + gas fees (~0.001 SOL)
Attack profit: 10,000 SOL
ROI: 999,900%
```

**Timeline:**
```
T+0s:   Attacker creates vault with 0.01 SOL
T+1s:   Attacker withdraws 0.02 SOL (triggers underflow)
T+2s:   Vault balance = 18,446,744,073 SOL
T+3s:   Attacker withdraws protocol's 10,000 SOL
T+4s:   Protocol is insolvent
T+60s:  Attacker bridges funds to another chain
T+5min: First victim notices missing funds
```

## Checked Arithmetic Methods

Rust provides several methods for safe arithmetic:

### 1. checked_* Methods (Recommended)
```rust
let result = balance.checked_sub(amount);
// Returns: Option<u64>
//   Some(result) if valid
//   None if would overflow/underflow
```

**Available methods:**
```rust
checked_add(x)      // Addition
checked_sub(x)      // Subtraction
checked_mul(x)      // Multiplication
checked_div(x)      // Division
checked_rem(x)      // Remainder
checked_pow(x)      // Exponentiation
```

**Usage pattern:**
```rust
vault.balance = vault.balance
    .checked_sub(amount)
    .ok_or(CustomError::InsufficientFunds)?;
```

### 2. saturating_* Methods (Use Carefully)
```rust
let result = balance.saturating_sub(amount);
// Returns: u64 (never None)
//   Clamps to 0 on underflow
//   Clamps to MAX on overflow
```

**Example:**
```rust
let balance: u64 = 10;
let withdrawal: u64 = 20;

let result = balance.saturating_sub(withdrawal);
// result = 0 (clamped, not wrapped)
```

**⚠️ Warning:** Can hide logic errors. Use only when clamping is desired behavior.

### 3. wrapping_* Methods (Explicit Wrapping)
```rust
let result = balance.wrapping_sub(amount);
// Explicitly allows wrapping (same as -= in release mode)
```

**Use case:** Intentional modular arithmetic (cryptography, hashing).

### 4. overflowing_* Methods (Advanced)
```rust
let (result, overflowed) = balance.overflowing_sub(amount);
if overflowed {
    return Err(CustomError::Overflow.into());
}
```

**Returns:** `(result, bool)` where bool indicates if overflow occurred.

## Proper Error Handling

### Pattern 1: checked_* with ok_or
```rust
pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    
    vault.balance = vault.balance
        .checked_sub(amount)
        .ok_or(CustomError::InsufficientFunds)?;
    
    Ok(())
}
```

**How it works:**
1. `checked_sub(amount)` returns `Option<u64>`
2. `ok_or(error)` converts to `Result<u64, Error>`
   - `Some(x)` → `Ok(x)`
   - `None` → `Err(CustomError::InsufficientFunds)`
3. `?` operator propagates error, aborting transaction

### Pattern 2: require! with Checked Math
```rust
pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    
    let new_balance = vault.balance
        .checked_sub(amount)
        .ok_or(CustomError::InsufficientFunds)?;
    
    require!(
        new_balance >= MINIMUM_BALANCE,
        CustomError::BelowMinimum
    );
    
    vault.balance = new_balance;
    Ok(())
}
```

### Pattern 3: Manual Check (Explicit)
```rust
pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    
    require!(
        vault.balance >= amount,
        CustomError::InsufficientFunds
    );
    
    vault.balance -= amount;  // Safe: checked above
    Ok(())
}
```

**⚠️ Caution:** Only safe because we checked first. Prefer `checked_sub` for defense in depth.

### Pattern 4: Multiple Operations
```rust
pub fn complex_math(ctx: Context<Math>, a: u64, b: u64, c: u64) -> Result<()> {
    // Chain checked operations
    let result = a
        .checked_mul(b)
        .and_then(|x| x.checked_add(c))
        .and_then(|x| x.checked_div(10))
        .ok_or(CustomError::ArithmeticError)?;
    
    ctx.accounts.value = result;
    Ok(())
}
```

### Custom Error Definitions
```rust
#[error_code]
pub enum CustomError {
    #[msg("The requested withdrawal amount exceeds the vault balance.")]
    InsufficientFunds,
    
    #[msg("Balance would fall below minimum required amount.")]
    BelowMinimum,
    
    #[msg("Arithmetic operation overflowed.")]
    ArithmeticError,
    
    #[msg("Division by zero.")]
    DivisionByZero,
}
```

## Code Comparison

### Vulnerable Version
```rust
// ❌ VULNERABLE CODE
#[program]
pub mod unsafe_arithmetic_vuln {
    use super::*;

    pub fn withdraw(ctx: Context<WithdrawVuln>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        
        vault.balance -= amount;  // ← WRAPS ON UNDERFLOW
        
        Ok(())
    }
}

#[derive(Accounts)]
pub struct WithdrawVuln<'info> {
    #[account(mut, has_one = owner)]
    pub vault: Account<'info, Vault>,
    pub owner: Signer<'info>,
}

#[account]
pub struct Vault {
    pub balance: u64,
    pub owner: Pubkey,
}
```

**Test case:**
```rust
#[test]
fn test_underflow_exploit() {
    // Create vault with 100 lamports
    let vault = create_vault(owner, 100);
    
    // Withdraw 101 lamports
    withdraw(vault, 101);
    
    // Check balance
    let vault_data = get_vault(vault);
    assert_eq!(vault_data.balance, 18_446_744_073_709_551_615);
    // ❌ VULNERABLE: Balance wrapped to max u64
}
```

### Secure Version
```rust
// ✅ SECURE CODE
#[program]
pub mod unsafe_arithmetic_fix {
    use super::*;

    pub fn withdraw(ctx: Context<WithdrawSafe>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        
        // Checked arithmetic prevents underflow
        vault.balance = vault.balance
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

#[account]
pub struct Vault {
    pub balance: u64,
    pub owner: Pubkey,
}

#[error_code]
pub enum CustomError {
    #[msg("The requested withdrawal amount exceeds the vault balance.")]
    InsufficientFunds,
}
```

**Test case:**
```rust
#[test]
fn test_underflow_prevented() {
    // Create vault with 100 lamports
    let vault = create_vault(owner, 100);
    
    // Try to withdraw 101 lamports
    let result = withdraw(vault, 101);
    
    // Should fail with InsufficientFunds error
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err(),
        ProgramError::Custom(CustomError::InsufficientFunds as u32)
    );
    
    // Balance unchanged
    let vault_data = get_vault(vault);
    assert_eq!(vault_data.balance, 100);
    // ✅ SECURE: Transaction aborted, balance protected
}
```

## Testing with Pinocchio

### Installation
```bash
# Install Pinocchio
# Pinocchio is included as a workspace dependency

# Add to project
pinocchio = { workspace = true }
```

### Comprehensive Test Suite

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use pinocchio_test::*;

    #[test]
    fn test_normal_withdrawal() {
        let mut context = ProgramTest::default();
        let owner = Keypair::new();
        
        let vault = create_vault(&mut context, &owner, 1000);
        
        // Normal withdrawal: 500 lamports
        let result = withdraw(&mut context, vault, &owner, 500);
        assert!(result.is_ok());
        
        let vault_data = get_account::<Vault>(&context, vault);
        assert_eq!(vault_data.balance, 500);
    }

    #[test]
    fn test_exact_balance_withdrawal() {
        let mut context = ProgramTest::default();
        let owner = Keypair::new();
        
        let vault = create_vault(&mut context, &owner, 1000);
        
        // Withdraw exact balance
        let result = withdraw(&mut context, vault, &owner, 1000);
        assert!(result.is_ok());
        
        let vault_data = get_account::<Vault>(&context, vault);
        assert_eq!(vault_data.balance, 0);
    }

    #[test]
    fn test_underflow_attack() {
        let mut context = ProgramTest::default();
        let owner = Keypair::new();
        
        let vault = create_vault(&mut context, &owner, 100);
        
        // ATTACK: Withdraw more than balance
        let result = withdraw(&mut context, vault, &owner, 101);
        
        // Fixed version: Should fail
        assert!(result.is_err());
        
        // Vulnerable version: Would succeed with wrapped balance
        // assert_eq!(vault.balance, 18_446_744_073_709_551_615);
    }

    #[test]
    fn test_zero_balance_underflow() {
        let mut context = ProgramTest::default();
        let owner = Keypair::new();
        
        let vault = create_vault(&mut context, &owner, 0);
        
        // Try to withdraw from empty vault
        let result = withdraw(&mut context, vault, &owner, 1);
        assert!(result.is_err());
        
        let vault_data = get_account::<Vault>(&context, vault);
        assert_eq!(vault_data.balance, 0);
    }

    #[test]
    fn test_max_value_overflow() {
        let mut context = ProgramTest::default();
        let owner = Keypair::new();
        
        // Create vault with near-max balance
        let vault = create_vault(&mut context, &owner, u64::MAX - 10);
        
        // Try to deposit (if deposit function exists)
        let result = deposit(&mut context, vault, &owner, 20);
        
        // Should fail with overflow error
        assert!(result.is_err());
    }

    #[test]
    fn test_sequential_withdrawals() {
        let mut context = ProgramTest::default();
        let owner = Keypair::new();
        
        let vault = create_vault(&mut context, &owner, 1000);
        
        // Multiple withdrawals
        withdraw(&mut context, vault, &owner, 300).unwrap();
        withdraw(&mut context, vault, &owner, 200).unwrap();
        withdraw(&mut context, vault, &owner, 400).unwrap();
        
        let vault_data = get_account::<Vault>(&context, vault);
        assert_eq!(vault_data.balance, 100);
        
        // This should fail (only 100 left)
        let result = withdraw(&mut context, vault, &owner, 101);
        assert!(result.is_err());
    }
}
```

### Running Tests

```bash
# Test vulnerable version
cd programs/03a-unsafe-arithmetic-vuln
cargo test-sbf

# Test fixed version
cd programs/03b-unsafe-arithmetic-fix
cargo test-sbf

# Run with detailed output
cargo test-sbf -- --nocapture --test-threads=1

# Run specific test
cargo test-sbf test_underflow_attack

# Run with Solana logs
RUST_LOG=solana_runtime::system_instruction_processor=trace cargo test-sbf
```

### Expected Outputs

**Vulnerable Version:**
```
running 6 tests
test test_normal_withdrawal ... ok
test test_exact_balance_withdrawal ... ok
test test_underflow_attack ... FAILED
  ⚠️  Security vulnerability: Underflow allowed
  Expected: Transaction failure
  Actual: Balance = 18446744073709551615
test test_zero_balance_underflow ... FAILED
test test_max_value_overflow ... FAILED
test test_sequential_withdrawals ... ok

failures:
  test_underflow_attack
  test_zero_balance_underflow
  test_max_value_overflow
```

**Fixed Version:**
```
running 6 tests
test test_normal_withdrawal ... ok
  ✅ Withdrew 500, balance now 500
test test_exact_balance_withdrawal ... ok
  ✅ Withdrew entire balance, vault now empty
test test_underflow_attack ... ok
  ✅ Underflow prevented
  Error: InsufficientFunds
test test_zero_balance_underflow ... ok
  ✅ Cannot withdraw from empty vault
test test_max_value_overflow ... ok
  ✅ Overflow prevented in deposit
test test_sequential_withdrawals ... ok
  ✅ Final withdrawal correctly rejected

test result: ok. 6 passed; 0 failed
```

## Key Takeaways

### For Developers

1. **Always use checked arithmetic** for balance updates and financial calculations:
   ```rust
   ✅ balance.checked_sub(amount).ok_or(Error)?
   ❌ balance -= amount
   ```

2. **Understand release mode behavior**: Overflow/underflow wraps silently in production.

3. **Test edge cases**:
   - Withdrawing more than balance
   - Operations on zero balances
   - Operations near u64::MAX
   - Sequential operations

4. **Use descriptive errors**: Help users understand why transactions fail.

5. **Document assumptions**: If you use saturating_* or wrapping_*, explain why.

### For Auditors

1. **Search for arithmetic operators**: Any `+=`, `-=`, `*=`, `/=` on balances is suspicious.

2. **Check for unchecked methods**: `wrapping_*`, `saturating_*` without clear justification.

3. **Verify error handling**: Ensure checked operations have proper error cases.

4. **Test boundary conditions**: Attempt underflows, overflows, and edge cases.

### Checklist for Safe Arithmetic

```rust
// ✅ Safe patterns
amount.checked_add(x)           // Addition
amount.checked_sub(x)           // Subtraction  
amount.checked_mul(x)           // Multiplication
amount.checked_div(x)           // Division
require!(a >= b, Error)         // Explicit check before operation

// ⚠️ Use with caution
amount.saturating_sub(x)        // Only if clamping is intended
amount.wrapping_add(x)          // Only for modular arithmetic

// ❌ Never use for balances
amount += x                     // Wraps on overflow
amount -= x                     // Wraps on underflow
amount *= x                     // Wraps on overflow
```

### Common Vulnerable Operations

| Operation | Risk | Secure Alternative |
|-----------|------|-------------------|
| `balance -= amount` | Underflow to max value | `balance.checked_sub(amount)?` |
| `balance += amount` | Overflow to 0 | `balance.checked_add(amount)?` |
| `shares * price` | Overflow in multiplication | `shares.checked_mul(price)?` |
| `total / count` | Division by zero | `total.checked_div(count)?` |
| `base ** exponent` | Massive overflow | `base.checked_pow(exp)?` |

## Further Reading

- [Rust Checked Math Documentation](https://doc.rust-lang.org/std/primitive.u64.html#method.checked_sub) - Complete reference for checked_* methods
- [Anchor Error Handling](https://www.anchor-lang.com/docs/errors) - Using `require!` and `error_code`
- [Solana Arithmetic Pitfalls](https://github.com/coral-xyz/sealevel-attacks/tree/master/programs/8-arithmetic-overflow) - Official Sealevel attack examples
- [Pinocchio Testing Framework](https://github.com/anza-xyz/pinocchio) - Fast local testing
- [Integer Overflow in Smart Contracts](https://consensys.github.io/smart-contract-best-practices/attacks/insecure-arithmetic/) - General blockchain context

## License

This example is part of the Solana Security Examples repository and is provided for educational purposes.
