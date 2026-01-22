# Signer Privilege Escalation

## Table of Contents
1. [Introduction](#introduction)
2. [Distinction from Incorrect Authority Check](#distinction-from-incorrect-authority-check)
3. [Understanding Privilege Escalation](#understanding-privilege-escalation)
4. [The Vulnerability Explained](#the-vulnerability-explained)
5. [How Any Signer Can Escalate Privileges](#how-any-signer-can-escalate-privileges)
6. [The Pause/Unpause Attack Scenario](#the-pauseunpause-attack-scenario)
7. [Multi-Layered Security](#multi-layered-security)
8. [Defense in Depth](#defense-in-depth)
9. [Code Comparison](#code-comparison)
10. [Testing with Pinocchio](#testing-with-pinocchio)
11. [Key Takeaways](#key-takeaways)

## Introduction

Signer privilege escalation is a subtle but critical vulnerability that allows **any wallet** to execute privileged operations intended only for authorized administrators. While similar to incorrect authority checks (Example 02), this vulnerability focuses specifically on **privilege escalation** through global state manipulation rather than simple parameter modification.

**Key Distinction:**
- **Example 02 (Authority Check)**: Any signer can modify fee parameters
- **Example 05 (Privilege Escalation)**: Any signer can pause the entire protocol, gaining emergency admin powers

This vulnerability represents a different threat model:
- **Authority bugs**: Attackers modify protocol parameters (fees, rates)
- **Privilege escalation**: Attackers gain administrative powers (pause, upgrade, emergency shutdown)

**Real-world impact:**
- Protocol-wide DoS (denial of service)
- Emergency power abuse
- Governance takeover
- User fund freezing

## Distinction from Incorrect Authority Check

### Example 02: Authority Validation
**Focus**: Parameter modification without permission
```rust
// Any signer can modify fee_bps
pub fn set_fee(ctx: Context<SetFeeVuln>, new_fee: u16) -> Result<()> {
    ctx.accounts.config.fee_bps = new_fee;  // ❌ No authority check
    Ok(())
}
```

**Impact**: Financial manipulation (fees, rates, limits)

### Example 05: Privilege Escalation
**Focus**: Gaining administrative powers
```rust
// Any signer can toggle global pause state
pub fn toggle_pause(ctx: Context<TogglePauseVuln>) -> Result<()> {
    let settings = &mut ctx.accounts.settings;
    settings.paused = !settings.paused;  // ❌ No owner check
    Ok(())
}
```

**Impact**: Protocol-wide control (pause, emergency, governance)

### Why This Distinction Matters

**Authority bugs are about "what you can modify"**
- Change a number (fee, rate, limit)
- Limited blast radius
- Often reversible

**Privilege escalation is about "what powers you gain"**
- Control protocol state (pause/unpause)
- Wider blast radius
- May be irreversible (emergency modes)

### Comparison Table

| Aspect | Example 02: Authority | Example 05: Privilege Escalation |
|--------|----------------------|----------------------------------|
| **Vulnerability** | Missing authority binding | Missing owner verification |
| **Attack** | Modify fee parameters | Pause entire protocol |
| **Impact** | Fee manipulation | Protocol DoS |
| **Scope** | Single parameter | Global state |
| **Blast Radius** | Transactions using that parameter | All protocol operations |
| **Reversibility** | Admin can change fee back | May require emergency recovery |
| **Threat Level** | Financial manipulation | Administrative takeover |

## Understanding Privilege Escalation

### What is Privilege Escalation?

In security, privilege escalation occurs when a user gains access to resources or functions beyond their authorization level:

**Types:**
1. **Vertical**: User → Admin (gaining higher privileges)
2. **Horizontal**: User A → User B (accessing peer resources)

### In Blockchain Context

**Traditional Web Application:**
```javascript
// Privilege escalation in web app
app.post('/admin/pause', (req, res) => {
  // ❌ Missing authentication check
  systemState.paused = true;
  res.send('System paused');
});

// Any user can access /admin/pause
```

**Solana Program:**
```rust
// Privilege escalation in Solana
pub fn toggle_pause(ctx: Context<TogglePauseVuln>) -> Result<()> {
    // ❌ Missing owner check
    ctx.accounts.settings.paused = !ctx.accounts.settings.paused;
    Ok(())
}

// Any signer can toggle pause state
```

### Why This is Critical for Pause Functions

**Pause functions are emergency controls:**
- Stop all protocol operations
- Protect against active exploits
- Allow time for emergency responses
- Should only be accessible to trusted parties

**If anyone can pause:**
- Griefing attacks (repeatedly pause protocol)
- DoS (deny service to all users)
- Ransom attacks (pause until demands met)
- Reputation damage

## The Vulnerability Explained

### Vulnerable Code Analysis

From `example5.rs`:

```rust
#[program]
pub mod signer_privilege_vuln {
    use super::*;

    pub fn toggle_pause(ctx: Context<TogglePauseVuln>) -> Result<()> {
        let settings = &mut ctx.accounts.settings;
        
        // ❌ NO VERIFICATION that anyone == settings.owner
        settings.paused = !settings.paused;
        
        Ok(())
    }
}

#[derive(Accounts)]
pub struct TogglePauseVuln<'info> {
    #[account(mut)]
    pub settings: Account<'info, Settings>,  // ✅ Type-checked
                                              // ❌ No owner binding
    
    pub anyone: Signer<'info>,  // ✅ Signature verified
                                // ❌ Identity not checked
}

#[account]
pub struct Settings {
    pub owner: Pubkey,   // ← EXISTS but NEVER CHECKED
    pub paused: bool,
}
```

### The Critical Mistake

**What the code does:**
1. ✅ Verifies `settings` is owned by this program
2. ✅ Verifies `settings` has the correct discriminator (is a `Settings` account)
3. ✅ Verifies `anyone` signed the transaction
4. ❌ **NEVER** verifies `anyone.key() == settings.owner`

**What the attacker exploits:**
```rust
// Anchor only checks:
// 1. settings is a valid Settings account ✅
// 2. anyone provided a signature ✅

// Anchor does NOT check:
// 3. anyone is the stored owner ❌
```

### Why Developers Make This Mistake

**Common misconception:**
> "The `owner` field exists in the Settings account, so the program knows who the owner is."

**Reality:**
- The program *stores* who the owner is
- But it doesn't *enforce* that only the owner can call the function
- You must explicitly use `has_one = owner` constraint

**Analogy:**
```
Having a lock on your door (owner field) doesn't mean it's engaged.
You still need to check if the person opening the door has the key (has_one constraint).
```

## How Any Signer Can Escalate Privileges

### Attack Mechanism

**Step 1: Reconnaissance**
```bash
# Attacker finds the Settings account
$ solana account Settings111...

Owner: YourProtocol111...
Data:
  owner: Admin111...        ← Legitimate owner
  paused: false             ← Current state
```

**Step 2: Generate Attack Wallet**
```typescript
const attacker = Keypair.generate();

// Fund with minimal SOL for transaction fee
await connection.requestAirdrop(
  attacker.publicKey,
  0.001 * LAMPORTS_PER_SOL
);
```

**Step 3: Execute Privilege Escalation**
```typescript
// Attacker calls toggle_pause with THEIR OWN wallet
const tx = await program.methods
  .togglePause()
  .accounts({
    settings: settingsAccount,
    anyone: attacker.publicKey,  // ← Attacker's wallet, NOT admin
  })
  .signers([attacker])  // ← Attacker signs with their own key
  .rpc();

console.log("✅ Protocol paused by non-admin!");
```

**Step 4: Verify Escalation**
```typescript
const settingsData = await program.account.settings.fetch(settingsAccount);
console.log(`Paused: ${settingsData.paused}`);  // true

// Attacker now has effective admin power over pause state
```

### Why This Works

**Anchor's validation process:**
```rust
// What Anchor checks:
1. settings.owner == program_id  ✅ (Anchor's built-in check)
2. settings.discriminator == Settings::discriminator()  ✅
3. anyone.is_signer == true  ✅

// What Anchor does NOT check:
4. anyone.key() == settings.owner  ❌ (requires has_one)
```

**The missing link:**
```rust
// This is what's needed but missing:
require_keys_eq!(
    ctx.accounts.settings.owner,
    ctx.accounts.anyone.key(),
    ErrorCode::Unauthorized
);
```

## The Pause/Unpause Attack Scenario

### Scenario: DeFi Protocol Under Attack

**Protocol Details:**
- Total Value Locked: $50 million
- Daily Volume: $10 million
- Users: 50,000 active traders
- Pause function: Emergency control for exploits

### Attack Timeline

**T-5 minutes: Preparation**
```typescript
// Attacker prepares
const attacker = Keypair.generate();
await fundWallet(attacker, 0.01 * LAMPORTS_PER_SOL);

// Find Settings account
const [settings] = PublicKey.findProgramAddressSync(
  [Buffer.from("settings")],
  programId
);
```

**T-0: Initial Pause**
```typescript
// Attacker pauses protocol
await program.methods
  .togglePause()
  .accounts({
    settings,
    anyone: attacker.publicKey,  // Non-admin
  })
  .signers([attacker])
  .rpc();

console.log("⚠️ Protocol PAUSED by attacker");
```

**Impact at T+0:**
- All trading halted
- All deposits blocked
- All withdrawals frozen
- Users panic
- Social media erupts

**T+5 minutes: Ransom Demand**
```typescript
// Attacker posts on social media
"I control the pause state. Send 100 SOL to [address] or protocol stays paused."
```

**T+10 minutes: Admin Attempts Recovery**
```typescript
// Admin tries to unpause
await program.methods
  .togglePause()
  .accounts({
    settings,
    anyone: admin.publicKey,  // Legitimate admin
  })
  .signers([admin])
  .rpc();

console.log("✅ Protocol UNPAUSED by admin");
```

**T+11 minutes: Attacker Re-pauses**
```typescript
// Attacker immediately pauses again
await program.methods
  .togglePause()
  .accounts({
    settings,
    anyone: attacker.publicKey,
  })
  .signers([attacker])
  .rpc();

console.log("⚠️ Protocol PAUSED again by attacker");
```

**T+30 minutes: Continuous Battle**
- Attacker and admin repeatedly toggle pause
- Protocol unstable
- Users lose confidence
- Funds start exiting

**T+2 hours: Protocol Response**
- Emergency program upgrade deployed
- Users must be notified
- Damage to reputation: severe
- Lost volume for the day: $10 million

### Economic Impact

**Direct Costs:**
- Lost trading fees: $50,000/day
- Emergency deployment: $10,000
- Incident response: $25,000

**Indirect Costs:**
- User trust: immeasurable
- Competitor migration: 10-20% of users
- Future investor confidence: damaged
- Legal/regulatory scrutiny: potential

**Total estimated impact: $500,000 - $5,000,000**

### Griefing Attack Variant

**Attacker doesn't want ransom, just chaos:**
```typescript
// Automated griefing bot
setInterval(async () => {
  await program.methods
    .togglePause()
    .accounts({
      settings,
      anyone: attacker.publicKey,
    })
    .signers([attacker])
    .rpc();
  
  console.log("🔄 Toggled pause state");
}, 5000);  // Every 5 seconds

// Protocol becomes unusable
// Admin can't keep up
// Users abandon platform
```

## Multi-Layered Security

### Layer 1: Type Safety (✅ Present)
```rust
pub settings: Account<'info, Settings>
```
**What it protects:**
- ✅ Settings is owned by program
- ✅ Settings has correct discriminator
- ✅ Settings deserializes correctly

**What it DOESN'T protect:**
- ❌ Who can modify Settings

### Layer 2: Signature Verification (✅ Present)
```rust
pub owner: Signer<'info>
```
**What it protects:**
- ✅ Transaction is signed
- ✅ Signature is valid

**What it DOESN'T protect:**
- ❌ That the signer is authorized

### Layer 3: Authority Binding (❌ MISSING in vulnerable code)
```rust
#[account(mut, has_one = owner)]
pub settings: Account<'info, Settings>,
pub owner: Signer<'info>
```
**What it protects:**
- ✅ Signer matches stored owner
- ✅ Only authorized user can call
- ✅ Privilege escalation prevented

### The Security Pyramid

```
                    /\
                   /  \
                  /Auth\        ← Layer 3: Who is authorized?
                 /------\
                /Signature\     ← Layer 2: Who signed?
               /----------\
              /   Type     \    ← Layer 1: What is this account?
             /--------------\
```

**Each layer is necessary but insufficient alone:**
- Layer 1 alone: Wrong account type can't be passed
- Layer 1+2: Correct account type + someone signed
- Layer 1+2+3: Correct account type + authorized user signed ✅

## Defense in Depth

### Defense 1: has_one Constraint (Primary)
```rust
#[account(
    mut,
    has_one = owner @ CustomError::Unauthorized
)]
pub settings: Account<'info, Settings>,
pub owner: Signer<'info>
```

**How it works:**
```rust
// Anchor generates this check:
if settings.owner != owner.key() {
    return Err(CustomError::Unauthorized.into());
}
```

**Benefits:**
- ✅ Automatic enforcement
- ✅ Zero-cost abstraction
- ✅ Clear intent in code

### Defense 2: Manual Validation (Fallback)
```rust
pub fn toggle_pause(ctx: Context<TogglePause>) -> Result<()> {
    // Explicit check
    require_keys_eq!(
        ctx.accounts.settings.owner,
        ctx.accounts.caller.key(),
        ErrorCode::Unauthorized
    );
    
    ctx.accounts.settings.paused = !ctx.accounts.settings.paused;
    Ok(())
}
```

**When to use:**
- Complex authorization logic
- Multiple possible authorized signers
- Dynamic authorization rules

### Defense 3: Time Locks (Advanced)
```rust
#[account]
pub struct Settings {
    pub owner: Pubkey,
    pub paused: bool,
    pub pause_requested_at: i64,     // Timestamp
    pub pause_delay: i64,             // Required delay in seconds
}

pub fn request_pause(ctx: Context<RequestPause>) -> Result<()> {
    let settings = &mut ctx.accounts.settings;
    settings.pause_requested_at = Clock::get()?.unix_timestamp;
    Ok(())
}

pub fn execute_pause(ctx: Context<ExecutePause>) -> Result<()> {
    let settings = &mut ctx.accounts.settings;
    let now = Clock::get()?.unix_timestamp;
    
    require!(
        now >= settings.pause_requested_at + settings.pause_delay,
        ErrorCode::TimeLockNotExpired
    );
    
    settings.paused = true;
    Ok(())
}
```

**Benefits:**
- Prevents instant griefing
- Gives time for community response
- Reduces impact of compromised keys

### Defense 4: Multi-Sig (Best Practice)
```rust
#[account]
pub struct Settings {
    pub owners: [Pubkey; 3],          // Multiple owners
    pub required_approvals: u8,        // M-of-N threshold
    pub paused: bool,
    pub pending_pause: PendingPause,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct PendingPause {
    pub approved_by: Vec<Pubkey>,
    pub total_approvals: u8,
}

pub fn approve_pause(ctx: Context<ApprovePause>) -> Result<()> {
    let settings = &mut ctx.accounts.settings;
    
    // Check if signer is one of the owners
    require!(
        settings.owners.contains(&ctx.accounts.signer.key()),
        ErrorCode::NotOwner
    );
    
    // Add approval
    settings.pending_pause.approved_by.push(ctx.accounts.signer.key());
    settings.pending_pause.total_approvals += 1;
    
    // If threshold met, execute pause
    if settings.pending_pause.total_approvals >= settings.required_approvals {
        settings.paused = true;
    }
    
    Ok(())
}
```

**Benefits:**
- Prevents single point of failure
- Requires consensus
- Harder to compromise

### Defense 5: Role-Based Access Control (RBAC)
```rust
#[account]
pub struct Settings {
    pub super_admin: Pubkey,    // Can pause, unpause, change admin
    pub pause_admin: Pubkey,    // Can only pause (emergency)
    pub unpause_admin: Pubkey,  // Can only unpause (recovery)
    pub paused: bool,
}

pub fn toggle_pause(ctx: Context<TogglePause>) -> Result<()> {
    let settings = &mut ctx.accounts.settings;
    let signer = ctx.accounts.signer.key();
    
    // Check role
    if settings.paused {
        // Unpausing: requires unpause_admin or super_admin
        require!(
            signer == settings.unpause_admin || signer == settings.super_admin,
            ErrorCode::UnauthorizedToUnpause
        );
    } else {
        // Pausing: requires pause_admin or super_admin
        require!(
            signer == settings.pause_admin || signer == settings.super_admin,
            ErrorCode::UnauthorizedToPause
        );
    }
    
    settings.paused = !settings.paused;
    Ok(())
}
```

**Benefits:**
- Separation of concerns
- Granular permissions
- Reduced blast radius

## Code Comparison

### Vulnerable Version

```rust
// ❌ VULNERABLE CODE
#[program]
pub mod signer_privilege_vuln {
    use super::*;

    pub fn toggle_pause(ctx: Context<TogglePauseVuln>) -> Result<()> {
        let settings = &mut ctx.accounts.settings;
        
        // ❌ No verification that anyone is authorized
        settings.paused = !settings.paused;
        
        Ok(())
    }
}

#[derive(Accounts)]
pub struct TogglePauseVuln<'info> {
    #[account(mut)]  // ← Only marks as writable, no authorization
    pub settings: Account<'info, Settings>,
    
    pub anyone: Signer<'info>,  // ← Only verifies signature exists
}

#[account]
pub struct Settings {
    pub owner: Pubkey,   // ← Field exists but NEVER CHECKED
    pub paused: bool,
}
```

**Attack:**
```typescript
// Any wallet can pause the protocol
const randomAttacker = Keypair.generate();

await program.methods
  .togglePause()
  .accounts({
    settings: settingsAccount,
    anyone: randomAttacker.publicKey,  // ← Not the owner!
  })
  .signers([randomAttacker])
  .rpc();

// ✅ Transaction succeeds (bad!)
// Protocol is now paused by unauthorized user
```

### Secure Version

```rust
// ✅ SECURE CODE
#[program]
pub mod signer_privilege_fix {
    use super::*;

    pub fn toggle_pause(ctx: Context<TogglePauseSafe>) -> Result<()> {
        let settings = &mut ctx.accounts.settings;
        
        // ✅ If we reach here, owner verification passed
        settings.paused = !settings.paused;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct TogglePauseSafe<'info> {
    #[account(
        mut,
        has_one = owner  // ← THE FIX: Verifies owner.key() == settings.owner
    )]
    pub settings: Account<'info, Settings>,
    
    pub owner: Signer<'info>,  // ← Must be the stored owner
}

#[account]
pub struct Settings {
    pub owner: Pubkey,   // ← Now ENFORCED by has_one constraint
    pub paused: bool,
}
```

**Attack attempt:**
```typescript
// Attacker tries to pause with their wallet
const attacker = Keypair.generate();

await program.methods
  .togglePause()
  .accounts({
    settings: settingsAccount,
    owner: attacker.publicKey,  // ← Not the stored owner
  })
  .signers([attacker])
  .rpc();

// ❌ Transaction fails with error:
// Error: AnchorError caused by account: settings.
// Error Code: ConstraintHasOne.
// Error Message: A has_one constraint was violated.
```

**Legitimate use:**
```typescript
// Admin (legitimate owner) pauses protocol
const admin = loadKeypairFromFile("admin.json");

await program.methods
  .togglePause()
  .accounts({
    settings: settingsAccount,
    owner: admin.publicKey,  // ← Matches settings.owner
  })
  .signers([admin])
  .rpc();

// ✅ Transaction succeeds (good!)
// Protocol paused by authorized admin
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
    fn test_owner_can_toggle_pause() {
        let mut context = ProgramTest::default();
        let owner = Keypair::new();
        
        // Create settings with owner
        let settings = create_settings(&mut context, &owner);
        
        // Owner pauses protocol
        let result = toggle_pause(&mut context, settings, &owner);
        assert!(result.is_ok());
        
        // Verify paused
        let settings_data = get_account::<Settings>(&context, settings);
        assert_eq!(settings_data.paused, true);
        
        // Owner unpauses protocol
        let result = toggle_pause(&mut context, settings, &owner);
        assert!(result.is_ok());
        
        // Verify unpaused
        let settings_data = get_account::<Settings>(&context, settings);
        assert_eq!(settings_data.paused, false);
    }

    #[test]
    fn test_non_owner_cannot_pause() {
        let mut context = ProgramTest::default();
        let owner = Keypair::new();
        let attacker = Keypair::new();
        
        let settings = create_settings(&mut context, &owner);
        
        // Attacker tries to pause
        let result = toggle_pause(&mut context, settings, &attacker);
        
        // Should fail
        assert!(result.is_err());
        
        // Vulnerable version: would succeed (bad)
        // Fixed version: fails with ConstraintHasOne (good)
        assert_eq!(
            result.unwrap_err(),
            ProgramError::Custom(ErrorCode::ConstraintHasOne as u32)
        );
        
        // Verify state unchanged
        let settings_data = get_account::<Settings>(&context, settings);
        assert_eq!(settings_data.paused, false);
    }

    #[test]
    fn test_privilege_escalation_attack() {
        let mut context = ProgramTest::default();
        let owner = Keypair::new();
        
        let settings = create_settings(&mut context, &owner);
        
        // Generate 10 random attackers
        let attackers: Vec<Keypair> = (0..10)
            .map(|_| Keypair::new())
            .collect();
        
        // Each attacker tries to pause
        for attacker in attackers {
            let result = toggle_pause(&mut context, settings, &attacker);
            
            // All should fail
            assert!(result.is_err());
        }
        
        // Verify protocol still unpaused
        let settings_data = get_account::<Settings>(&context, settings);
        assert_eq!(settings_data.paused, false);
    }

    #[test]
    fn test_griefing_attack_prevention() {
        let mut context = ProgramTest::default();
        let owner = Keypair::new();
        let attacker = Keypair::new();
        
        let settings = create_settings(&mut context, &owner);
        
        // Owner legitimately pauses
        toggle_pause(&mut context, settings, &owner).unwrap();
        
        // Attacker tries to unpause (griefing)
        let result = toggle_pause(&mut context, settings, &attacker);
        assert!(result.is_err());
        
        // Verify still paused (attacker failed)
        let settings_data = get_account::<Settings>(&context, settings);
        assert_eq!(settings_data.paused, true);
        
        // Only owner can unpause
        toggle_pause(&mut context, settings, &owner).unwrap();
        let settings_data = get_account::<Settings>(&context, settings);
        assert_eq!(settings_data.paused, false);
    }

    #[test]
    fn test_owner_field_matches_signer() {
        let mut context = ProgramTest::default();
        let owner = Keypair::new();
        
        let settings = create_settings(&mut context, &owner);
        let settings_data = get_account::<Settings>(&context, settings);
        
        // Verify owner field is set correctly
        assert_eq!(settings_data.owner, owner.pubkey());
        
        // Verify only this specific owner can toggle
        let result = toggle_pause(&mut context, settings, &owner);
        assert!(result.is_ok());
    }

    #[test]
    fn test_multiple_owners_separate_settings() {
        let mut context = ProgramTest::default();
        let owner1 = Keypair::new();
        let owner2 = Keypair::new();
        
        let settings1 = create_settings(&mut context, &owner1);
        let settings2 = create_settings(&mut context, &owner2);
        
        // Owner1 can only modify settings1
        assert!(toggle_pause(&mut context, settings1, &owner1).is_ok());
        assert!(toggle_pause(&mut context, settings1, &owner2).is_err());
        
        // Owner2 can only modify settings2
        assert!(toggle_pause(&mut context, settings2, &owner2).is_ok());
        assert!(toggle_pause(&mut context, settings2, &owner1).is_err());
    }
}
```

### Running Tests

```bash
# Test vulnerable version
cd programs/05a-signer-privilege-escalation-vuln
cargo test-sbf

# Test fixed version
cd programs/05b-signer-privilege-escalation-fix
cargo test-sbf

# Run with verbose output
cargo test-sbf -- --nocapture --test-threads=1

# Run specific test
cargo test-sbf test_privilege_escalation_attack

# Run all security tests
cargo test-sbf test_non_owner test_privilege test_griefing
```

### Expected Outputs

**Vulnerable Version:**
```
running 6 tests
test test_owner_can_toggle_pause ... ok
test test_non_owner_cannot_pause ... FAILED
  ⚠️  Security vulnerability: Non-owner can pause
  Expected: Transaction failure
  Actual: Transaction success
  Protocol paused by unauthorized user
test test_privilege_escalation_attack ... FAILED
  ⚠️  All 10 attackers successfully paused protocol
test test_griefing_attack_prevention ... FAILED
  ⚠️  Attacker successfully unpaused protocol
test test_owner_field_matches_signer ... ok
test test_multiple_owners_separate_settings ... FAILED
  ⚠️  Owner1 can modify Owner2's settings

failures:
  test_non_owner_cannot_pause
  test_privilege_escalation_attack
  test_griefing_attack_prevention
  test_multiple_owners_separate_settings
```

**Fixed Version:**
```
running 6 tests
test test_owner_can_toggle_pause ... ok
  ✅ Owner successfully toggled pause: false → true → false
test test_non_owner_cannot_pause ... ok
  ✅ Non-owner correctly blocked
  Error: ConstraintHasOne
test test_privilege_escalation_attack ... ok
  ✅ All 10 attackers blocked
  Protocol remains unpaused
test test_griefing_attack_prevention ... ok
  ✅ Attacker cannot unpause
  Only owner can toggle state
test test_owner_field_matches_signer ... ok
  ✅ Owner field correctly enforced
test test_multiple_owners_separate_settings ... ok
  ✅ Owner isolation maintained
  Owner1 → Settings1 ✅
  Owner1 → Settings2 ❌
  Owner2 → Settings2 ✅
  Owner2 → Settings1 ❌

test result: ok. 6 passed; 0 failed
```

## Key Takeaways

### For Developers

1. **Signer ≠ Authorization**: Having a signature doesn't mean the signer is authorized.

2. **Use has_one for all owner checks**: Don't rely on the field existing; enforce the relationship.

3. **Treat pause functions as critical**: They're emergency controls and need the strongest protections.

4. **Layer your defenses**:
   - Type safety (Account<T>)
   - Signature verification (Signer)
   - Authority binding (has_one)

5. **Test unauthorized access**: Every privileged function should have tests with unauthorized signers.

### For Auditors

1. **Look for pause/emergency functions**: These are high-value targets for privilege escalation.

2. **Check for has_one on admin fields**: Any owner/admin field should have corresponding has_one.

3. **Verify signature ≠ authorization**: Presence of Signer doesn't mean proper authorization.

4. **Test with random wallets**: Attempt to call privileged functions with unauthorized signers.

5. **Consider griefing attacks**: Can attackers repeatedly toggle state to DoS the protocol?

### Common Patterns

✅ **Secure:**
```rust
#[account(mut, has_one = owner)]
pub settings: Account<'info, Settings>,
pub owner: Signer<'info>
```

✅ **Also secure (manual):**
```rust
require_keys_eq!(
    settings.owner,
    caller.key(),
    ErrorCode::Unauthorized
);
```

❌ **Vulnerable:**
```rust
#[account(mut)]
pub settings: Account<'info, Settings>,
pub anyone: Signer<'info>  // ← No authority binding!
```

### Security Checklist

- [ ] All privileged functions have authority checks
- [ ] `has_one` used for admin/owner relationships
- [ ] Custom error messages for authorization failures
- [ ] Tests for unauthorized access attempts
- [ ] Tests for griefing scenarios
- [ ] Documentation of who can call privileged functions
- [ ] Consideration of multi-sig or time-locks for critical functions

## Further Reading

- [Anchor has_one Constraint](https://www.anchor-lang.com/docs/attributes#has_one) - Official documentation
- [Solana Access Control](https://docs.solana.com/developing/programming-model/accounts#signers) - Understanding signers
- [Privilege Escalation Attacks](https://owasp.org/www-community/attacks/Privilege_escalation) - OWASP guide
- [Multi-Sig Patterns](https://book.anchor-lang.com/anchor_in_depth/multisig.html) - Implementing multi-sig
- [Pinocchio Testing](https://github.com/anza-xyz/pinocchio) - Fast local testing framework

## License

This example is part of the Solana Security Examples repository and is provided for educational purposes.
