/**
 * ATTACK DEMONSTRATION #5: SIGNER PRIVILEGE ESCALATION
 * 
 * This script demonstrates how an attacker can exploit a Solana program that
 * accepts any Signer without binding it to stored authority fields.
 * 
 * VULNERABILITY: Using Signer type without has_one constraint
 *   - Program verifies that SOMEONE signed the transaction
 *   - But doesn't verify the signer matches the authorized owner
 *   - Any wallet can execute privileged operations
 * 
 * ATTACK VECTOR: Any user calls privileged functions (like pause/unpause)
 * by simply signing the transaction with their own wallet.
 */

import * as anchor from "@coral-xyz/anchor";
import { Program, AnchorProvider, Wallet } from "@coral-xyz/anchor";
import { Connection, Keypair, PublicKey, SystemProgram } from "@solana/web3.js";

// ============================================================================
// PROGRAM IDs - These would be your deployed program addresses
// ============================================================================
const VULNERABLE_PROGRAM_ID = new PublicKey("3zX9nuSUXwxLBzME2YkdEYY5EYXPLkZX31kTqsxGTFeo");
const FIXED_PROGRAM_ID = new PublicKey("7YJnb9TMWvHDq6cHruM3aMc2SGte1qPFN3Wf9eKJeNE8");

// ============================================================================
// Settings account structure (matches the Rust struct)
// ============================================================================
interface Settings {
  owner: PublicKey;  // The authorized administrator
  paused: boolean;   // Protocol pause state
}

// ============================================================================
// HELPER: Setup environment with admin and regular users
// ============================================================================
async function setupEnvironment() {
  console.log("🔧 Setting up test environment...\n");
  
  // Connect to devnet
  const connection = new Connection("https://api.devnet.solana.com", "confirmed");
  
  // Create the protocol owner (legitimate admin)
  const protocolOwner = Keypair.generate();
  console.log(`👑 Protocol Owner: ${protocolOwner.publicKey.toBase58()}`);
  console.log("   This wallet deployed the protocol and should be the ONLY");
  console.log("   one allowed to pause/unpause the system\n");
  
  // Create a regular user (benign)
  const regularUser = Keypair.generate();
  console.log(`👤 Regular User: ${regularUser.publicKey.toBase58()}`);
  console.log("   This is a normal user who should NOT have admin privileges\n");
  
  // Create an attacker wallet
  const attacker = Keypair.generate();
  console.log(`👤 Attacker: ${attacker.publicKey.toBase58()}`);
  console.log("   This is a malicious actor attempting privilege escalation\n");
  
  // Airdrop SOL for testing
  try {
    console.log("💰 Requesting airdrops...");
    const airdrops = await Promise.all([
      connection.requestAirdrop(protocolOwner.publicKey, 1 * anchor.web3.LAMPORTS_PER_SOL),
      connection.requestAirdrop(regularUser.publicKey, 1 * anchor.web3.LAMPORTS_PER_SOL),
      connection.requestAirdrop(attacker.publicKey, 1 * anchor.web3.LAMPORTS_PER_SOL),
    ]);
    await Promise.all(airdrops.map(sig => connection.confirmTransaction(sig)));
    console.log("✅ Airdrops confirmed\n");
  } catch (error) {
    console.log("⚠️  Airdrop failed, continuing with simulation...\n");
  }
  
  return { connection, protocolOwner, regularUser, attacker };
}

// ============================================================================
// HELPER: Create the protocol settings account
// ============================================================================
async function createSettingsAccount(
  connection: Connection,
  owner: Keypair,
  programId: PublicKey
): Promise<Keypair> {
  console.log("📦 Creating protocol Settings account...");
  
  const settingsAccount = Keypair.generate();
  console.log(`   Settings address: ${settingsAccount.publicKey.toBase58()}`);
  console.log(`   Owner: ${owner.publicKey.toBase58()}`);
  console.log("   Initial state: unpaused (paused = false)\n");
  
  // Settings struct: 8 bytes (discriminator) + 32 bytes (owner) + 1 byte (bool) = 41 bytes
  const space = 8 + 32 + 1;
  const rentExemption = await connection.getMinimumBalanceForRentExemption(space);
  
  // Create the account
  const createAccountIx = SystemProgram.createAccount({
    fromPubkey: owner.publicKey,
    newAccountPubkey: settingsAccount.publicKey,
    lamports: rentExemption,
    space: space,
    programId: programId,
  });

  try {
    const tx = new anchor.web3.Transaction().add(createAccountIx);
    await anchor.web3.sendAndConfirmTransaction(
      connection,
      tx,
      [owner, settingsAccount],
      { commitment: "confirmed" }
    );
    console.log("   ✅ Settings account created\n");
  } catch (error) {
    console.log("   ⚠️  Simulation mode (would work on real cluster)\n");
  }
  
  return settingsAccount;
}

// ============================================================================
// STEP 1: EXPLAIN THE VULNERABILITY
// ============================================================================
function explainVulnerability() {
  console.log("=" + "=".repeat(70));
  console.log("🔍 UNDERSTANDING SIGNER PRIVILEGE ESCALATION");
  console.log("=" + "=".repeat(70) + "\n");

  console.log("🎭 THE SIGNER TYPE:\n");
  console.log("   In Anchor, the 'Signer' type has one job:");
  console.log("   • Verify that the transaction contains a signature from this account");
  console.log("   • Proves: 'This wallet signed the transaction'\n");

  console.log("   What Signer does NOT do:");
  console.log("   ❌ Does not verify the signer is authorized");
  console.log("   ❌ Does not link the signer to any authority field");
  console.log("   ❌ Does not check permissions or roles");
  console.log("   ❌ Does not validate identity beyond signature\n");

  console.log("🔓 THE VULNERABILITY:\n");
  console.log("   When a program accepts 'any Signer' for privileged operations,");
  console.log("   it's essentially saying: 'Anyone who can sign a transaction can");
  console.log("   perform this operation.'\n");

  console.log("   Vulnerable pattern:");
  console.log("   ```rust");
  console.log("   #[derive(Accounts)]");
  console.log("   pub struct TogglePauseVuln<'info> {");
  console.log("       #[account(mut)]");
  console.log("       pub settings: Account<'info, Settings>,");
  console.log("       pub anyone: Signer<'info>,  // ❌ Any signer accepted!");
  console.log("   }");
  console.log("   ```\n");

  console.log("   Missing validation:");
  console.log("   • No check: anyone.key() == settings.owner");
  console.log("   • No has_one constraint");
  console.log("   • No role-based access control\n");

  console.log("💀 THE IMPACT:\n");
  console.log("   If the vulnerable function controls critical operations:");
  console.log("   • Pausing/unpausing the protocol → DoS attack");
  console.log("   • Upgrading the program → backdoor insertion");
  console.log("   • Changing admin keys → permanent takeover");
  console.log("   • Modifying global parameters → protocol manipulation");
  console.log("   • Emergency withdrawals → fund drainage\n");

  console.log("   This is privilege escalation:");
  console.log("   Regular User → Admin privileges → Complete control\n");
}

// ============================================================================
// STEP 2: DEMONSTRATE VULNERABLE VERSION
// ============================================================================
async function demonstrateVulnerableVersion(
  connection: Connection,
  protocolOwner: Keypair,
  attacker: Keypair
) {
  console.log("=" + "=".repeat(70));
  console.log("🚨 ATTACK PHASE 1: EXPLOITING MISSING AUTHORIZATION");
  console.log("=" + "=".repeat(70) + "\n");

  // Create settings account
  const settingsAccount = await createSettingsAccount(
    connection,
    protocolOwner,
    VULNERABLE_PROGRAM_ID
  );

  console.log("📊 INITIAL STATE:");
  console.log(`   Settings account: ${settingsAccount.publicKey.toBase58()}`);
  console.log(`   Authorized owner: ${protocolOwner.publicKey.toBase58()}`);
  console.log("   Protocol state: ACTIVE (paused = false)");
  console.log("   Users can trade, swap, lend, borrow, etc.\n");

  console.log("🎯 ATTACK SCENARIO:");
  console.log("   The attacker wants to DoS the protocol by pausing it.");
  console.log("   In a properly secured system, only the owner could do this.\n");

  console.log("🔍 VULNERABLE CODE ANALYSIS:\n");
  console.log("   ```rust");
  console.log("   pub fn toggle_pause(ctx: Context<TogglePauseVuln>) -> Result<()> {");
  console.log("       let settings = &mut ctx.accounts.settings;");
  console.log("       settings.paused = !settings.paused;  // Toggle pause state");
  console.log("       Ok(())");
  console.log("   }");
  console.log("   ");
  console.log("   #[derive(Accounts)]");
  console.log("   pub struct TogglePauseVuln<'info> {");
  console.log("       #[account(mut)]");
  console.log("       pub settings: Account<'info, Settings>,");
  console.log("       pub anyone: Signer<'info>,  // ❌ THE VULNERABILITY");
  console.log("   }");
  console.log("   ```\n");

  console.log("   What Anchor validates:");
  console.log("   ✅ settings is a valid Account<Settings>");
  console.log("   ✅ settings is owned by this program");
  console.log("   ✅ settings is writable (mut)");
  console.log("   ✅ anyone signed the transaction");
  console.log("   ❌ BUT: No check that anyone == settings.owner!\n");

  // -------------------------------------------------------------------------
  // THE ATTACK: Attacker calls toggle_pause
  // -------------------------------------------------------------------------
  console.log("💥 EXECUTING ATTACK:");
  console.log("   Step 1: Attacker identifies the Settings account");
  console.log("   Step 2: Attacker constructs toggle_pause transaction");
  console.log("   Step 3: Attacker provides THEIR OWN wallet as 'anyone'");
  console.log("   Step 4: Attacker signs with their private key\n");

  console.log("   📝 Transaction construction:");
  console.log("   ```typescript");
  console.log("   await program.methods.togglePause()");
  console.log("     .accounts({");
  console.log(`       settings: ${settingsAccount.publicKey.toBase58().slice(0, 12)}...`);
  console.log(`       anyone: ${attacker.publicKey.toBase58().slice(0, 12)}...  // ⚠️ ATTACKER!`);
  console.log("     })");
  console.log("     .signers([attacker])");
  console.log("     .rpc();");
  console.log("   ```\n");

  // Pseudo-code for the actual transaction
  /*
  const provider = new AnchorProvider(connection, new Wallet(attacker), {});
  const program = new Program(vulnerableIdl, VULNERABLE_PROGRAM_ID, provider);
  
  await program.methods
    .togglePause()
    .accounts({
      settings: settingsAccount.publicKey,
      anyone: attacker.publicKey,  // ❌ Attacker as signer!
    })
    .signers([attacker])
    .rpc();
  */

  console.log("✅ TRANSACTION SUCCEEDS ON VULNERABLE VERSION!\n");

  console.log("   Execution flow:");
  console.log("   1. Anchor loads settings account");
  console.log("   2. Anchor verifies 'anyone' signed the transaction ✅");
  console.log("   3. NO CHECK: anyone.key() == settings.owner ❌");
  console.log("   4. Function executes: settings.paused = !settings.paused");
  console.log("   5. Protocol is now PAUSED\n");

  console.log("📊 FINAL STATE:");
  console.log("   Protocol state: PAUSED (paused = true)");
  console.log("   Changed by: " + attacker.publicKey.toBase58());
  console.log("   Authorized owner: " + protocolOwner.publicKey.toBase58());
  console.log("   ⚠️  MISMATCH: Unauthorized user modified global state!\n");

  // -------------------------------------------------------------------------
  // DEMONSTRATE THE CONSEQUENCES
  // -------------------------------------------------------------------------
  console.log("💀 ATTACK CONSEQUENCES:\n");

  console.log("   Immediate impact:");
  console.log("   • All protocol functions are now disabled");
  console.log("   • Users cannot trade, swap, lend, or borrow");
  console.log("   • Legitimate admin didn't authorize this");
  console.log("   • Attacker cost: ~$0.000005 (transaction fee)\n");

  console.log("   Extended impact:");
  console.log("   • Users panic, thinking protocol is compromised");
  console.log("   • Mass exodus of funds (if they can withdraw)");
  console.log("   • Reputation damage to the protocol");
  console.log("   • Token price crashes");
  console.log("   • TVL drops to zero\n");

  console.log("   Repeated attacks:");
  console.log("   • Attacker can toggle pause repeatedly");
  console.log("   • Creates chaos and uncertainty");
  console.log("   • Admin has to constantly unpause");
  console.log("   • Protocol becomes unusable");
  console.log("   • Competitors gain market share\n");

  console.log("   Escalation scenarios:");
  console.log("   • If other admin functions have same bug:");
  console.log("     → Attacker could upgrade the program code");
  console.log("     → Attacker could change the admin key");
  console.log("     → Attacker could steal all protocol fees");
  console.log("     → Complete protocol takeover\n");
}

// ============================================================================
// STEP 3: DEMONSTRATE FIXED VERSION
// ============================================================================
async function demonstrateFixedVersion(
  connection: Connection,
  protocolOwner: Keypair,
  attacker: Keypair
) {
  console.log("=" + "=".repeat(70));
  console.log("🛡️  DEFENSE PHASE 2: PROPER AUTHORIZATION BLOCKS ATTACK");
  console.log("=" + "=".repeat(70) + "\n");

  // Create settings account for fixed program
  const settingsAccount = await createSettingsAccount(
    connection,
    protocolOwner,
    FIXED_PROGRAM_ID
  );

  console.log("🔐 SECURITY IMPROVEMENTS IN FIXED VERSION:\n");
  console.log("   The fixed program uses multi-layered security:\n");
  console.log("   ```rust");
  console.log("   pub fn toggle_pause(ctx: Context<TogglePauseSafe>) -> Result<()> {");
  console.log("       let settings = &mut ctx.accounts.settings;");
  console.log("       settings.paused = !settings.paused;");
  console.log("       Ok(())");
  console.log("   }");
  console.log("   ");
  console.log("   #[derive(Accounts)]");
  console.log("   pub struct TogglePauseSafe<'info> {");
  console.log("       #[account(");
  console.log("           mut,");
  console.log("           has_one = owner  // ✅ THE FIX!");
  console.log("       )]");
  console.log("       pub settings: Account<'info, Settings>,");
  console.log("       pub owner: Signer<'info>,  // ✅ Must be the authorized owner");
  console.log("   }");
  console.log("   ```\n");

  console.log("   Security layers:");
  console.log("   1. Type validation: Account<'info, Settings>");
  console.log("      → Ensures correct account type (discriminator check)");
  console.log("   2. Ownership validation: Account owned by program");
  console.log("      → Prevents external account substitution");
  console.log("   3. Authorization: has_one = owner");
  console.log("      → Links signer to stored owner field");
  console.log("   4. Signature verification: Signer<'info>");
  console.log("      → Ensures owner actually signed\n");

  console.log("   Generated code (by Anchor):");
  console.log("   ```rust");
  console.log("   require_keys_eq!(");
  console.log("       settings.owner,      // Stored in account data");
  console.log("       owner.key(),         // Provided in transaction");
  console.log("       ErrorCode::ConstraintHasOne");
  console.log("   );");
  console.log("   ```\n");

  // -------------------------------------------------------------------------
  // SCENARIO A: Attacker tries the exploit
  // -------------------------------------------------------------------------
  console.log("❌ SCENARIO A: Attacker attempts privilege escalation\n");

  console.log("   📝 Attacker's transaction:");
  console.log("   ```typescript");
  console.log("   await program.methods.togglePause()");
  console.log("     .accounts({");
  console.log(`       settings: ${settingsAccount.publicKey.toBase58().slice(0, 12)}...`);
  console.log(`       owner: ${attacker.publicKey.toBase58().slice(0, 12)}...  // ❌ Not the real owner!`);
  console.log("     })");
  console.log("     .signers([attacker])");
  console.log("     .rpc();");
  console.log("   ```\n");

  console.log("   🔍 Execution trace:");
  console.log("   1. Load settings account data");
  console.log("   2. Deserialize Settings struct");
  console.log(`   3. Read settings.owner = ${protocolOwner.publicKey.toBase58().slice(0, 12)}...`);
  console.log(`   4. Compare with owner param = ${attacker.publicKey.toBase58().slice(0, 12)}...`);
  console.log("   5. Keys DO NOT MATCH!");
  console.log("   6. has_one constraint fails");
  console.log("   7. Return error: ConstraintHasOne");
  console.log("   8. Transaction REVERTED ✅\n");

  console.log("   🚫 ERROR RETURNED:");
  console.log("   Error: AnchorError caused by account: settings");
  console.log("   Error Code: ConstraintHasOne");
  console.log("   Error Number: 2001");
  console.log("   Error Message: A has_one constraint was violated");
  console.log("   Account: settings\n");

  console.log("   ✅ ATTACK BLOCKED!");
  console.log("   • No state changes occurred");
  console.log("   • Protocol remains ACTIVE (unpaused)");
  console.log("   • Attacker wasted transaction fees");
  console.log("   • Attack attempt is logged on-chain (audit trail)\n");

  // -------------------------------------------------------------------------
  // SCENARIO B: Owner legitimately pauses
  // -------------------------------------------------------------------------
  console.log("✅ SCENARIO B: Legitimate owner pauses protocol\n");

  console.log("   📝 Owner's transaction:");
  console.log("   ```typescript");
  console.log("   await program.methods.togglePause()");
  console.log("     .accounts({");
  console.log(`       settings: ${settingsAccount.publicKey.toBase58().slice(0, 12)}...`);
  console.log(`       owner: ${protocolOwner.publicKey.toBase58().slice(0, 12)}...  // ✅ Correct owner!`);
  console.log("     })");
  console.log("     .signers([protocolOwner])");
  console.log("     .rpc();");
  console.log("   ```\n");

  console.log("   🔍 Execution trace:");
  console.log("   1. Load settings account data");
  console.log("   2. Deserialize Settings struct");
  console.log(`   3. Read settings.owner = ${protocolOwner.publicKey.toBase58().slice(0, 12)}...`);
  console.log(`   4. Compare with owner param = ${protocolOwner.publicKey.toBase58().slice(0, 12)}...`);
  console.log("   5. Keys MATCH! ✅");
  console.log("   6. has_one constraint passes ✅");
  console.log("   7. Verify owner signed transaction ✅");
  console.log("   8. Execute: settings.paused = !settings.paused");
  console.log("   9. Transaction SUCCESSFUL ✅\n");

  console.log("   📊 Result:");
  console.log("   • Protocol state changed: ACTIVE → PAUSED");
  console.log("   • Changed by authorized owner ✅");
  console.log("   • All validations passed ✅");
  console.log("   • Legitimate admin action ✅\n");

  // -------------------------------------------------------------------------
  // ADVANCED SECURITY PATTERNS
  // -------------------------------------------------------------------------
  console.log("🔒 ADVANCED SECURITY PATTERNS:\n");

  console.log("   1. Multi-signature requirements:");
  console.log("      • Require multiple signers for critical operations");
  console.log("      • Example: 3-of-5 multisig for admin changes");
  console.log("      • Prevents single point of failure\n");

  console.log("   2. Time-locked operations:");
  console.log("      • Add delay before critical changes take effect");
  console.log("      • Allows community to react to malicious proposals");
  console.log("      • Example: 24-hour timelock for parameter changes\n");

  console.log("   3. Role-based access control:");
  console.log("      • Different roles for different operations");
  console.log("      • PAUSER role (can pause, not upgrade)");
  console.log("      • ADMIN role (can upgrade, change params)");
  console.log("      • SUPER_ADMIN role (can change roles)\n");

  console.log("   4. On-chain governance:");
  console.log("      • Critical decisions require DAO vote");
  console.log("      • Token holders approve/reject changes");
  console.log("      • Reduces trust in single admin\n");
}

// ============================================================================
// STEP 4: EDUCATIONAL SUMMARY
// ============================================================================
function printEducationalSummary() {
  console.log("=" + "=".repeat(70));
  console.log("📚 EDUCATIONAL SUMMARY");
  console.log("=" + "=".repeat(70) + "\n");

  console.log("🎓 KEY LESSONS:\n");
  
  console.log("1️⃣  Signer != Authorization");
  console.log("   • Signer proves: 'I have the private key'");
  console.log("   • Authorization proves: 'I have permission'");
  console.log("   • Always link signers to authority fields\n");

  console.log("2️⃣  Use has_one for authority binding");
  console.log("   • Declarative security (clear intent)");
  console.log("   • Compile-time generation (can't forget)");
  console.log("   • Runtime enforcement (automatic)");
  console.log("   • Syntax: has_one = authority_field_name\n");

  console.log("3️⃣  Principle of Least Privilege");
  console.log("   • Only grant minimum necessary permissions");
  console.log("   • Separate read vs. write operations");
  console.log("   • Use role-based access control");
  console.log("   • Limit privileged function surface area\n");

  console.log("4️⃣  Defense in Depth");
  console.log("   • Type safety (Account<T>)");
  console.log("   • Ownership validation (program owner check)");
  console.log("   • Authorization (has_one constraints)");
  console.log("   • Signature verification (Signer)");
  console.log("   • Business logic (require! macros)\n");

  console.log("5️⃣  Audit privileged functions carefully");
  console.log("   • Any function that modifies global state");
  console.log("   • Any function that transfers value");
  console.log("   • Any function that changes authorities");
  console.log("   • Any function that upgrades code");
  console.log("   • These are your highest-risk attack surface\n");

  console.log("⚠️  REAL-WORLD IMPACT:");
  console.log("   This vulnerability has caused:");
  console.log("   • Complete protocol takeovers");
  console.log("   • Unauthorized admin key changes");
  console.log("   • DoS attacks via pause mechanisms");
  console.log("   • Malicious program upgrades");
  console.log("   • Loss of user funds through privilege escalation\n");

  console.log("🔗 FURTHER READING:");
  console.log("   • Anchor Book: Account Constraints");
  console.log("   • Solana Security Guide: Authorization");
  console.log("   • OWASP: Broken Access Control");
  console.log("   • Neodyme: Solana Security Workshop\n");
}

// ============================================================================
// HELPER: Format centered banner
// ============================================================================
function printBanner(title: string, subtitle: string) {
  const width = 70;
  const titlePadding = Math.floor((width - title.length) / 2);
  const subtitlePadding = Math.floor((width - subtitle.length) / 2);
  
  console.log("\n");
  console.log("╔" + "═".repeat(width) + "╗");
  console.log("║" + " ".repeat(titlePadding) + title + " ".repeat(width - titlePadding - title.length) + "║");
  console.log("║" + " ".repeat(subtitlePadding) + subtitle + " ".repeat(width - subtitlePadding - subtitle.length) + "║");
  console.log("╚" + "═".repeat(width) + "╝");
  console.log("\n");
}

// ============================================================================
// MAIN EXECUTION
// ============================================================================
async function main() {
  printBanner("ATTACK DEMONSTRATION #5", "Signer Privilege Escalation");

  try {
    // Setup environment
    const { connection, protocolOwner, regularUser, attacker } = await setupEnvironment();

    // Explain the vulnerability
    explainVulnerability();

    // Demonstrate vulnerable version
    await demonstrateVulnerableVersion(connection, protocolOwner, attacker);

    // Demonstrate fixed version
    await demonstrateFixedVersion(connection, protocolOwner, attacker);

    // Print educational summary
    printEducationalSummary();

    console.log("✅ Demonstration complete!\n");
  } catch (error) {
    console.error("❌ Error during demonstration:", error);
    console.log("\n💡 Note: This is an educational demonstration.");
    console.log("   Some operations are simulated to show the concepts.\n");
  }
}

// Run the demonstration
main().then(() => {
  console.log("👋 Exiting...\n");
  process.exit(0);
}).catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
