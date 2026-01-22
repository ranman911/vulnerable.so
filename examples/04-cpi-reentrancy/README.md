# CPI Misuse / Re-entrancy

## Table of Contents
1. [Introduction](#introduction)
2. [Understanding Cross-Program Invocations (CPI)](#understanding-cross-program-invocations-cpi)
3. [What is Re-entrancy?](#what-is-re-entrancy)
4. [The Vulnerability Explained](#the-vulnerability-explained)
5. [The CEI Pattern: Checks-Effects-Interactions](#the-cei-pattern-checks-effects-interactions)
6. [Lock Mechanisms](#lock-mechanisms)
7. [State Management Before External Calls](#state-management-before-external-calls)
8. [Attack Demonstration](#attack-demonstration)
9. [The Fix Explained](#the-fix-explained)
10. [Code Comparison](#code-comparison)
11. [Testing with Pinocchio](#testing-with-pinocchio)
12. [Key Takeaways](#key-takeaways)

## Introduction

Re-entrancy is one of the most infamous vulnerability classes in blockchain history, responsible for the **2016 DAO Hack** that resulted in a $60 million loss and led to the Ethereum/Ethereum Classic split. While Solana's architecture differs from Ethereum, **re-entrancy attacks are still possible through Cross-Program Invocations (CPI)**.

A re-entrancy attack occurs when:
1. Contract A calls Contract B (external call)
2. Contract B calls back into Contract A (re-entry)
3. Contract A's state from the first call is still active
4. Contract B manipulates Contract A's incomplete state

On Solana, this manifests through CPI:
1. Your program calls another program via `invoke()` or `invoke_signed()`
2. The called program (potentially malicious) calls back into your program
3. Your program's state is updated **after** the CPI
4. The re-entrant call sees stale state and can exploit it

**Key differences from Ethereum:**
- Ethereum: Re-entrancy happens across multiple transactions
- Solana: Re-entrancy happens **within a single transaction** via CPI
- Solana: All state changes are rolled back if any instruction fails (atomicity)

## Understanding Cross-Program Invocations (CPI)

### What is CPI?

CPI allows one Solana program to call instructions in another program:

```rust
use anchor_lang::solana_program::program::invoke;

// Calling another program
invoke(
    &instruction,           // The instruction to execute
    &[account_info_1, account_info_2],  // Accounts needed
)?;
```

### Common CPI Use Cases

1. **Token Transfers**: Calling the Token Program
   ```rust
   invoke(
       &spl_token::instruction::transfer(
           &token_program,
           &source,
           &destination,
           &authority,
           amount,
       )?,
       &[source_info, dest_info, authority_info],
   )?;
   ```

2. **System Transfers**: Calling the System Program
   ```rust
   invoke(
       &system_instruction::transfer(&from, &to, amount),
       &[from_info, to_info],
   )?;
   ```

3. **Custom Program Calls**: Calling your own or third-party programs
   ```rust
   invoke(
       &custom_instruction,
       &[account1, account2],
   )?;
   ```

### CPI Security Risks

**Risk 1: Untrusted Programs**
- You might call a malicious program
- The program can execute arbitrary logic
- It can call back into your program

**Risk 2: State Inconsistency**
- If you update state **after** CPI
- Re-entrant calls see old state
- Attackers can exploit this window

**Risk 3: Account Manipulation**
- Called program can modify shared accounts
- Changes visible to your program immediately
- Can bypass invariants

## What is Re-entrancy?

### Classic Example: Ethereum DAO Hack

**Vulnerable contract (simplified):**
```solidity
function withdraw() public {
    uint amount = balances[msg.sender];
    
    // External call BEFORE state update
    (bool success,) = msg.sender.call{value: amount}("");
    require(success);
    
    // State updated AFTER external call
    balances[msg.sender] = 0;  // ❌ TOO LATE
}
```

**Attack:**
```solidity
// Attacker's malicious contract
receive() external payable {
    if (address(victim).balance > 0) {
        victim.withdraw();  // Re-enter!
    }
}

// Execution trace:
// 1. Attacker calls withdraw() → balance = 100
// 2. Victim sends 100 ETH to attacker
// 3. Attacker's receive() is triggered
// 4. Attacker calls withdraw() AGAIN → balance STILL = 100 (not updated yet!)
// 5. Victim sends another 100 ETH
// 6. Repeat until drained
```

### Solana Re-entrancy via CPI

**Vulnerable Solana program:**
```rust
pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    
    // CPI BEFORE state update
    invoke(
        &system_instruction::transfer(
            &vault.key(),
            &recipient.key(),
            amount
        ),
        &[vault_info, recipient_info],
    )?;
    
    // State updated AFTER CPI
    vault.balance -= amount;  // ❌ TOO LATE (and unchecked!)
    Ok(())
}
```

**Attack via malicious CPI target:**
```rust
// Attacker's program (called via CPI)
pub fn malicious_callback(ctx: Context<Callback>) -> Result<()> {
    // Re-enter victim's withdraw function
    invoke(
        &victim_withdraw_instruction,
        &[vault, attacker_recipient],
    )?;
    
    // Victim's vault.balance hasn't been updated yet!
    // Second withdrawal succeeds with stale balance
    Ok(())
}
```

## The Vulnerability Explained

### Vulnerable Code Analysis

From `example4.rs`:

```rust
pub fn withdraw(ctx: Context<WithdrawVuln>, amount: u64) -> Result<()> {
    let vault_key = ctx.accounts.vault.key();
    let recipient_key = ctx.accounts.recipient.key();
    let vault_info = ctx.accounts.vault.to_account_info();
    let recipient_info = ctx.accounts.recipient.to_account_info();
    let attacker_info = ctx.accounts.attacker_program.to_account_info();
    
    let vault = &mut ctx.accounts.vault;

    // ❌ VULNERABILITY #1: CPI to potentially malicious program
    invoke(
        &Instruction {
            program_id: ctx.accounts.attacker_program.key(),
            accounts: vec![
                AccountMeta::new_readonly(vault_key, false),
                AccountMeta::new_readonly(*ctx.program_id, false),
            ],
            data: [0].to_vec(),  // Hook before state update
        },
        &[vault_info.clone(), attacker_info],
    ).ok();  // Continues even if hook fails

    // ❌ VULNERABILITY #2: Funds transferred BEFORE state update
    invoke(
        &system_instruction::transfer(&vault_key, &recipient_key, amount),
        &[vault_info, recipient_info],
    )?;

    // ❌ VULNERABILITY #3: State updated LAST (wrong order!)
    vault.balance = vault.balance.saturating_sub(amount);
    Ok(())
}
```

### The Three Critical Mistakes

**Mistake 1: External Call Before State Update**
```rust
// Wrong order:
invoke(external_program)?;      // ← Attacker gains control here
vault.balance -= amount;        // ← Hasn't happened yet during re-entry
```

**Mistake 2: Using saturating_sub Instead of checked_sub**
```rust
vault.balance = vault.balance.saturating_sub(amount);
// If balance = 100 and amount = 200:
//   saturating_sub returns 0 (clamps)
//   checked_sub would return Error
// Attacker can withdraw all funds, balance goes to 0
```

**Mistake 3: No Re-entrancy Guard**
```rust
// No protection against recursive calls
// Attacker can call withdraw() from within the CPI callback
```

## The CEI Pattern: Checks-Effects-Interactions

The **Checks-Effects-Interactions** pattern is the gold standard for preventing re-entrancy.

### 1. Checks (Validation)
```rust
// Validate all inputs and preconditions FIRST
require!(!vault.is_locked, CustomError::ReentrancyBlocked);
require!(amount > 0, CustomError::InvalidAmount);
require!(vault.balance >= amount, CustomError::InsufficientFunds);
```

### 2. Effects (State Changes)
```rust
// Update all state BEFORE any external calls
vault.is_locked = true;
vault.balance = vault.balance.checked_sub(amount).ok_or(Error)?;
```

### 3. Interactions (External Calls)
```rust
// External calls LAST
invoke(&transfer_instruction, &accounts)?;
invoke(&hook_instruction, &accounts).ok();

// Unlock after all external calls succeed
vault.is_locked = false;
```

### Why This Works

**Without CEI (vulnerable):**
```
1. Call external program
   ↓
2. External program re-enters
   ↓
3. Sees old state (balance not updated)
   ↓
4. Withdraws again based on stale balance
   ↓
5. Original call updates state
   ↓
6. Balance is wrong (doesn't account for re-entrant withdrawal)
```

**With CEI (secure):**
```
1. Update state (balance -= amount)
   ↓
2. Call external program
   ↓
3. External program re-enters
   ↓
4. Sees new state (balance already updated)
   ↓
5. Insufficient funds error (balance too low)
   ↓
6. Re-entrant call fails
```

## Lock Mechanisms

### Boolean Lock (Recommended for Solana)

```rust
#[account]
pub struct Vault {
    pub is_locked: bool,  // Re-entrancy guard
    pub authority: Pubkey,
    pub balance: u64,
}

pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    
    // Check lock
    require!(!vault.is_locked, CustomError::ReentrancyBlocked);
    
    // Acquire lock
    vault.is_locked = true;
    
    // ... do work (state updates, CPIs) ...
    
    // Release lock
    vault.is_locked = false;
    Ok(())
}
```

### How the Lock Works

**Normal execution:**
```
Call 1: withdraw(100)
  └─> is_locked = false ✅
  └─> Set is_locked = true
  └─> Update balance
  └─> CPI to external program
      └─> External program does its thing
  └─> Set is_locked = false
  └─> Return success
```

**Re-entrancy attempt:**
```
Call 1: withdraw(100)
  └─> is_locked = false ✅
  └─> Set is_locked = true
  └─> Update balance
  └─> CPI to malicious program
      └─> Malicious program calls withdraw(100) again
          └─> is_locked = true ❌
          └─> Error: ReentrancyBlocked
          └─> Call 2 fails
  └─> Set is_locked = false
  └─> Return success
```

### Lock Patterns

**Pattern 1: Simple Lock**
```rust
require!(!vault.is_locked, Error::Locked);
vault.is_locked = true;

// ... work ...

vault.is_locked = false;
```

**Pattern 2: RAII-Style Lock (with defer pattern)**
```rust
pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    
    require!(!vault.is_locked, Error::Locked);
    vault.is_locked = true;
    
    // Use a defer-like pattern (Rust doesn't have defer, but we can structure code)
    let result = (|| -> Result<()> {
        // All logic here
        vault.balance = vault.balance.checked_sub(amount)?;
        invoke(&transfer, &accounts)?;
        Ok(())
    })();
    
    // Always unlock, even if error
    vault.is_locked = false;
    result
}
```

**Pattern 3: Per-User Locks**
```rust
#[account]
pub struct UserAccount {
    pub is_locked: bool,     // Per-user lock
    pub user: Pubkey,
    pub balance: u64,
}

// Each user has their own lock
// Prevents one user's transaction from blocking others
```

## State Management Before External Calls

### Rule: Commit State Before CPI

**Wrong:**
```rust
// ❌ State changes after CPI
pub fn vulnerable(ctx: Context<Vuln>, amount: u64) -> Result<()> {
    invoke(&external_call)?;           // CPI first
    ctx.accounts.vault.balance -= amount;  // State second
    Ok(())
}
```

**Right:**
```rust
// ✅ State changes before CPI
pub fn secure(ctx: Context<Secure>, amount: u64) -> Result<()> {
    ctx.accounts.vault.balance -= amount;  // State first
    invoke(&external_call)?;               // CPI second
    Ok(())
}
```

### Solana's Transaction Atomicity

**Key property:** If any instruction in a transaction fails, **all state changes are rolled back**.

```rust
pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
    // Update state
    vault.balance -= amount;  // Committed to transaction
    
    // External call
    invoke(&transfer, &accounts)?;  // If this fails...
    
    // Transaction is aborted, vault.balance rolls back
    Ok(())
}
```

**This means:**
- You can safely update state before CPI
- If the CPI fails, your state changes are reverted
- No need to manually roll back

### Multiple State Updates

**Pattern: Update all state before any CPI**
```rust
pub fn complex_operation(ctx: Context<Complex>) -> Result<()> {
    let state = &mut ctx.accounts.state;
    
    // ✅ All state updates first
    state.is_locked = true;
    state.balance = state.balance.checked_sub(amount)?;
    state.last_withdrawal = Clock::get()?.unix_timestamp;
    state.withdrawal_count += 1;
    
    // ✅ Then all CPIs
    invoke(&external_call_1)?;
    invoke(&external_call_2)?;
    
    // ✅ Finally unlock
    state.is_locked = false;
    Ok(())
}
```

## Attack Demonstration

### Scenario Setup

**Victim Program (Vulnerable):**
```rust
// programs/04a-cpi-reentrancy-vuln
pub fn withdraw(ctx: Context<WithdrawVuln>, amount: u64) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    
    // Calls attacker's program (hook)
    invoke(&attacker_hook_instruction)?;
    
    // Transfers funds
    invoke(&system_transfer)?;
    
    // Updates state (TOO LATE)
    vault.balance -= amount;
    Ok(())
}
```

**Attacker Program:**
```rust
// programs/cpi-reentrancy-attacker
pub fn reentrancy_hook(ctx: Context<Hook>) -> Result<()> {
    // Re-enter victim's withdraw function
    invoke(
        &victim_withdraw_instruction(100),
        &[vault, attacker],
    )?;
    
    // Victim's balance hasn't been updated yet!
    // This second withdrawal succeeds
    Ok(())
}
```

### Attack Execution

**Step 1: Setup**
```typescript
// Create vault with 1000 lamports
const vault = await createVault(authority, 1000);

// Deploy attacker program
const attackerProgram = await deployAttacker();
```

**Step 2: First Withdrawal (triggers re-entrancy)**
```typescript
// Call vulnerable withdraw with attacker program
await vulnerableProgram.methods
  .withdraw(new BN(100))
  .accounts({
    vault: vaultAccount,
    authority: authority.publicKey,
    recipient: attacker.publicKey,
    attackerProgram: attackerProgram,  // Malicious program
  })
  .signers([authority])
  .rpc();
```

**Step 3: Execution Flow**
```
Victim.withdraw(100):
  1. vault.balance = 1000
  2. invoke(attacker_hook)
     └─> Attacker.reentrancy_hook():
         └─> invoke(Victim.withdraw(100))  ← RE-ENTRY
             1. vault.balance STILL = 1000 (not updated yet!)
             2. invoke(attacker_hook) - might be called again
             3. transfer(vault → attacker, 100)
             4. vault.balance = 1000 - 100 = 900
             5. Return success
  3. transfer(vault → attacker, 100)
  4. vault.balance = 1000 - 100 = 900  ← WRONG (ignores re-entrant withdrawal)
  5. Return success

Final state:
  Attacker received: 200 lamports (100 + 100)
  Vault balance: 900 lamports
  Expected balance: 800 lamports
  Discrepancy: 100 lamports (loss)
```

### Multiple Re-entries

**Attacker can chain multiple re-entries:**
```rust
pub fn reentrancy_hook(ctx: Context<Hook>) -> Result<()> {
    let depth = get_stack_depth();
    
    if depth < 10 {  // Re-enter 10 times
        invoke(&victim_withdraw(100), &accounts)?;
    }
    
    Ok(())
}

// Result:
// 10 withdrawals of 100 = 1000 lamports stolen
// Vault.balance only decremented once = 900
// Attacker nets 900 lamports
```

## The Fix Explained

The secure version (`example4.fix.rs`) implements three key protections:

### Protection 1: Re-entrancy Lock

```rust
#[account]
pub struct Vault {
    pub is_locked: bool,  // ← Added lock field
    pub authority: Pubkey,
    pub balance: u64,
}

pub fn withdraw(ctx: Context<WithdrawSafe>, amount: u64) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    
    // Check lock
    require!(!vault.is_locked, CustomError::ReentrancyBlocked);
    
    // Acquire lock BEFORE any external calls
    vault.is_locked = true;
    
    // ... do work ...
    
    // Release lock AFTER all external calls
    vault.is_locked = false;
    Ok(())
}
```

### Protection 2: Checked Arithmetic

```rust
// ❌ Vulnerable (saturating)
vault.balance = vault.balance.saturating_sub(amount);

// ✅ Secure (checked)
vault.balance = vault.balance
    .checked_sub(amount)
    .ok_or(CustomError::InsufficientFunds)?;
```

### Protection 3: CEI Pattern

```rust
pub fn withdraw(ctx: Context<WithdrawSafe>, amount: u64) -> Result<()> {
    let vault = &mut ctx.accounts.vault;
    
    // CHECKS
    require!(!vault.is_locked, CustomError::ReentrancyBlocked);
    
    // EFFECTS
    vault.is_locked = true;
    vault.balance = vault.balance
        .checked_sub(amount)
        .ok_or(CustomError::InsufficientFunds)?;
    
    // INTERACTIONS
    invoke(&attacker_hook_instruction, &accounts).ok();
    invoke(&transfer_instruction, &accounts)?;
    
    vault.is_locked = false;
    Ok(())
}
```

### Why This Works

**Re-entrancy attempt with fixes:**
```
Call 1: withdraw(100)
  ├─> is_locked = false ✅
  ├─> Set is_locked = true
  ├─> balance = 1000 - 100 = 900 (updated BEFORE CPI)
  ├─> invoke(attacker_hook)
  │   └─> Call 2: withdraw(100)
  │       ├─> is_locked = true ❌
  │       └─> Error: ReentrancyBlocked
  │           Transaction fails
  ├─> (If re-entrancy succeeded, balance would be 900)
  ├─> (Second withdraw would fail: 900 - 100 = 800 ✅)
  └─> Return success

Result: Attack prevented by lock and state ordering
```

## Code Comparison

### Vulnerable Version

```rust
// ❌ VULNERABLE CODE
pub fn withdraw(ctx: Context<WithdrawVuln>, amount: u64) -> Result<()> {
    let vault_key = ctx.accounts.vault.key();
    let recipient_key = ctx.accounts.recipient.key();
    let vault_info = ctx.accounts.vault.to_account_info();
    let recipient_info = ctx.accounts.recipient.to_account_info();
    let attacker_info = ctx.accounts.attacker_program.to_account_info();
    
    let vault = &mut ctx.accounts.vault;

    // ❌ External call BEFORE state update
    invoke(
        &Instruction {
            program_id: ctx.accounts.attacker_program.key(),
            accounts: vec![
                AccountMeta::new_readonly(vault_key, false),
                AccountMeta::new_readonly(*ctx.program_id, false),
            ],
            data: [0].to_vec(),
        },
        &[vault_info.clone(), attacker_info],
    ).ok();

    // ❌ Transfer BEFORE state update
    invoke(
        &system_instruction::transfer(&vault_key, &recipient_key, amount),
        &[vault_info, recipient_info],
    )?;

    // ❌ State update LAST + saturating_sub
    vault.balance = vault.balance.saturating_sub(amount);
    Ok(())
}

#[account]
pub struct Vault {
    pub is_locked: bool,  // Field exists but NOT USED
    pub authority: Pubkey,
    pub balance: u64,
}
```

### Secure Version

```rust
// ✅ SECURE CODE
pub fn withdraw(ctx: Context<WithdrawSafe>, amount: u64) -> Result<()> {
    let vault_key = ctx.accounts.vault.key();
    let recipient_key = ctx.accounts.recipient.key();
    let victim_program = *ctx.program_id;
    let vault_info = ctx.accounts.vault.to_account_info();
    let recipient_info = ctx.accounts.recipient.to_account_info();
    let attacker_info = ctx.accounts.attacker_program.to_account_info();
    
    let vault = &mut ctx.accounts.vault;

    // ✅ CHECKS: Verify lock
    require!(!vault.is_locked, CustomError::ReentrancyBlocked);
    
    // ✅ EFFECTS: Update state FIRST
    vault.is_locked = true;  // Acquire lock
    vault.balance = vault.balance
        .checked_sub(amount)
        .ok_or(CustomError::InsufficientFunds)?;

    // ✅ INTERACTIONS: External calls LAST
    invoke(
        &Instruction {
            program_id: ctx.accounts.attacker_program.key(),
            accounts: vec![
                AccountMeta::new_readonly(vault_key, false),
                AccountMeta::new_readonly(victim_program, false),
            ],
            data: [0].to_vec(),
        },
        &[vault_info.clone(), attacker_info],
    ).ok();

    invoke(
        &system_instruction::transfer(&vault_key, &recipient_key, amount),
        &[vault_info, recipient_info],
    )?;

    vault.is_locked = false;  // Release lock
    Ok(())
}

#[error_code]
pub enum CustomError {
    #[msg("re-entrancy blocked")]
    ReentrancyBlocked,
    #[msg("insufficient funds")]
    InsufficientFunds,
}
```

## Testing with Pinocchio

### Installation

```bash
# Pinocchio is included as a workspace dependency
pinocchio = { workspace = true }
```

### Test Suite

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use pinocchio_test::*;

    #[test]
    fn test_normal_withdrawal() {
        let mut context = ProgramTest::default();
        let authority = Keypair::new();
        
        let vault = create_vault(&mut context, &authority, 1000);
        
        // Normal withdrawal
        let result = withdraw(
            &mut context,
            vault,
            &authority,
            100,
            &no_op_program,  // Non-malicious program
        );
        
        assert!(result.is_ok());
        
        let vault_data = get_account::<Vault>(&context, vault);
        assert_eq!(vault_data.balance, 900);
        assert_eq!(vault_data.is_locked, false);
    }

    #[test]
    fn test_reentrancy_attack() {
        let mut context = ProgramTest::default();
        let authority = Keypair::new();
        
        let vault = create_vault(&mut context, &authority, 1000);
        
        // Deploy attacker program
        let attacker = deploy_malicious_program(&mut context);
        
        // Attempt re-entrant withdrawal
        let result = withdraw(
            &mut context,
            vault,
            &authority,
            100,
            &attacker,  // Malicious program
        );
        
        // Fixed version: Should succeed but prevent re-entrancy
        assert!(result.is_ok());
        
        let vault_data = get_account::<Vault>(&context, vault);
        // Only one withdrawal should succeed
        assert_eq!(vault_data.balance, 900);
        
        // Vulnerable version would have:
        // assert_eq!(vault_data.balance, 900); // Wrong!
        // Actual balance should be 800 (two withdrawals)
    }

    #[test]
    fn test_lock_prevents_reentrancy() {
        let mut context = ProgramTest::default();
        let authority = Keypair::new();
        
        let vault = create_vault(&mut context, &authority, 1000);
        
        // Manually set lock
        let mut vault_data = get_account::<Vault>(&context, vault);
        vault_data.is_locked = true;
        set_account(&mut context, vault, &vault_data);
        
        // Try to withdraw while locked
        let result = withdraw(&mut context, vault, &authority, 100, &no_op_program);
        
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            ProgramError::Custom(CustomError::ReentrancyBlocked as u32)
        );
    }

    #[test]
    fn test_insufficient_funds_checked() {
        let mut context = ProgramTest::default();
        let authority = Keypair::new();
        
        let vault = create_vault(&mut context, &authority, 100);
        
        // Try to withdraw more than balance
        let result = withdraw(&mut context, vault, &authority, 200, &no_op_program);
        
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            ProgramError::Custom(CustomError::InsufficientFunds as u32)
        );
    }

    #[test]
    fn test_lock_released_after_success() {
        let mut context = ProgramTest::default();
        let authority = Keypair::new();
        
        let vault = create_vault(&mut context, &authority, 1000);
        
        withdraw(&mut context, vault, &authority, 100, &no_op_program).unwrap();
        
        let vault_data = get_account::<Vault>(&context, vault);
        assert_eq!(vault_data.is_locked, false);
    }
}
```

### Running Tests

```bash
# Test vulnerable version
cd programs/04a-cpi-reentrancy-vuln
cargo test-sbf

# Test fixed version
cd programs/04b-cpi-reentrancy-fix
cargo test-sbf

# Run with verbose output
cargo test-sbf -- --nocapture

# Test specific scenario
cargo test-sbf test_reentrancy_attack
```

### Expected Output

**Vulnerable Version:**
```
running 5 tests
test test_normal_withdrawal ... ok
test test_reentrancy_attack ... FAILED
  ⚠️  Re-entrancy vulnerability detected
  Expected balance: 800 (two withdrawals)
  Actual balance: 900 (only one deduction)
  Lost funds: 100 lamports
test test_lock_prevents_reentrancy ... FAILED
  Lock exists but is not checked
test test_insufficient_funds_checked ... FAILED
  Used saturating_sub instead of checked_sub
test test_lock_released_after_success ... ok
```

**Fixed Version:**
```
running 5 tests
test test_normal_withdrawal ... ok
  ✅ Normal withdrawal succeeded
  Balance: 1000 → 900
test test_reentrancy_attack ... ok
  ✅ Re-entrancy prevented
  Lock blocked second withdrawal
  Balance correctly: 900
test test_lock_prevents_reentrancy ... ok
  ✅ Lock check working
  Error: ReentrancyBlocked
test test_insufficient_funds_checked ... ok
  ✅ Checked arithmetic working
  Error: InsufficientFunds
test test_lock_released_after_success ... ok
  ✅ Lock properly released

test result: ok. 5 passed; 0 failed
```

## Key Takeaways

### For Developers

1. **Always follow CEI pattern**:
   - Checks (validation)
   - Effects (state changes)
   - Interactions (external calls)

2. **Use re-entrancy locks** for functions that make external calls.

3. **Update state before CPI**: Solana's atomicity protects you if CPI fails.

4. **Use checked arithmetic**: Never use saturating_* in financial code.

5. **Be paranoid about external calls**: Any CPI can potentially call back into your program.

### For Auditors

1. **Look for CPI before state updates**: Major red flag.

2. **Check for re-entrancy guards**: Look for `is_locked` or similar patterns.

3. **Verify lock usage**: Ensure locks are actually checked and released.

4. **Test re-entrancy**: Deploy malicious programs that call back.

5. **Check arithmetic**: Ensure `checked_*` methods are used.

### Common Patterns

✅ **Secure:**
```rust
vault.is_locked = true;
vault.balance -= amount;
invoke(&external_call)?;
vault.is_locked = false;
```

❌ **Vulnerable:**
```rust
invoke(&external_call)?;
vault.balance -= amount;
```

## Further Reading

- [Solana CPI Documentation](https://docs.solana.com/developing/programming-model/calling-between-programs) - Official CPI guide
- [The DAO Hack](https://hackingdistributed.com/2016/06/18/analysis-of-the-dao-exploit/) - Historical context
- [CEI Pattern](https://docs.soliditylang.org/en/latest/security-considerations.html#use-the-checks-effects-interactions-pattern) - Ethereum docs (applies to Solana)
- [Anchor Security](https://www.anchor-lang.com/docs/security) - Official security guidelines
- [Pinocchio Testing](https://github.com/anza-xyz/pinocchio) - Fast local testing

## License

This example is part of the Solana Security Examples repository and is provided for educational purposes.
