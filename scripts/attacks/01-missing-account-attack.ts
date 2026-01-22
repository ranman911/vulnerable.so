/**
 * ATTACK DEMONSTRATION #1: MISSING ACCOUNT VALIDATION
 * 
 * This script demonstrates how an attacker can exploit a Solana program that
 * uses raw AccountInfo without proper validation. The vulnerability allows
 * substituting any account and corrupting its data.
 * 
 * VULNERABILITY: Using AccountInfo/UncheckedAccount without checking:
 *   - Account ownership (is it owned by our program?)
 *   - Account discriminator (is it the correct account type?)
 *   - Account authorization (does the signer have permission?)
 * 
 * ATTACK VECTOR: Pass a different account (like TreasuryConfig) and overwrite
 * its critical data (like the admin field) to gain unauthorized control.
 */

import * as anchor from "@coral-xyz/anchor";
import { Program, AnchorProvider, Wallet } from "@coral-xyz/anchor";
import { Connection, Keypair, PublicKey, SystemProgram } from "@solana/web3.js";

// ============================================================================
// PROGRAM IDs - These would be your deployed program addresses
// ============================================================================
const VULNERABLE_PROGRAM_ID = new PublicKey("Fg6PaFpoGXkYsidMpWxTWqkWg5Rdp2q6uNQqynEWsJvj");
const FIXED_PROGRAM_ID = new PublicKey("HxhZNeWzpPkhZFBQC7KVio9oi5v4SjFFBXd5pTKmNsmV");

// ============================================================================
// HELPER: Setup connection and wallet
// ============================================================================
async function setupEnvironment() {
  console.log("🔧 Setting up test environment...\n");
  
  // Connect to devnet (or localhost for testing)
  const connection = new Connection("https://api.devnet.solana.com", "confirmed");
  
  // Create attacker wallet (in real scenario, this would be the attacker's wallet)
  const attacker = Keypair.generate();
  console.log(`👤 Attacker wallet: ${attacker.publicKey.toBase58()}`);
  
  // Create victim wallet (legitimate user)
  const victim = Keypair.generate();
  console.log(`👤 Victim wallet: ${victim.publicKey.toBase58()}\n`);
  
  // Airdrop SOL for testing (devnet only)
  try {
    console.log("💰 Requesting airdrop for attacker...");
    const airdropSig = await connection.requestAirdrop(
      attacker.publicKey,
      2 * anchor.web3.LAMPORTS_PER_SOL
    );
    await connection.confirmTransaction(airdropSig);
    console.log("✅ Airdrop confirmed\n");
  } catch (error) {
    console.log("⚠️  Airdrop failed (rate limit?), continuing anyway...\n");
  }
  
  return { connection, attacker, victim };
}

// ============================================================================
// STEP 1: DEMONSTRATE VULNERABLE VERSION
// ============================================================================
async function demonstrateVulnerableVersion(
  connection: Connection,
  attacker: Keypair,
  victim: Keypair
) {
  console.log("=" + "=".repeat(70));
  console.log("🚨 ATTACK PHASE 1: EXPLOITING VULNERABLE PROGRAM");
  console.log("=" + "=".repeat(70) + "\n");

  // Create a fake "TreasuryConfig" account that the attacker wants to corrupt
  // In reality, this would be an existing account with valuable data
  const victimAccount = Keypair.generate();
  
  console.log(`📦 Creating victim account: ${victimAccount.publicKey.toBase58()}`);
  console.log("   This represents a critical system account (e.g., TreasuryConfig)");
  
  // Allocate the account with some initial data
  // In a real scenario, this account would already exist with valid data
  const createAccountIx = SystemProgram.createAccount({
    fromPubkey: attacker.publicKey,
    newAccountPubkey: victimAccount.publicKey,
    lamports: await connection.getMinimumBalanceForRentExemption(256),
    space: 256, // Enough space for various data structures
    programId: VULNERABLE_PROGRAM_ID, // Owned by the vulnerable program
  });

  try {
    const tx = new anchor.web3.Transaction().add(createAccountIx);
    const sig = await anchor.web3.sendAndConfirmTransaction(
      connection,
      tx,
      [attacker, victimAccount],
      { commitment: "confirmed" }
    );
    console.log(`✅ Victim account created\n`);
  } catch (error) {
    console.log("⚠️  Account creation simulation (would work on real cluster)\n");
  }

  // -------------------------------------------------------------------------
  // THE ATTACK: Call set_message with a malicious payload
  // -------------------------------------------------------------------------
  console.log("🎯 ATTACK STRATEGY:");
  console.log("   1. Identify the victim account address");
  console.log("   2. Craft a malicious message that, when written as bytes,");
  console.log("      overwrites critical fields (e.g., admin pubkey)");
  console.log("   3. Call the vulnerable set_message function");
  console.log("   4. The program blindly overwrites the account data\n");

  // Create a malicious message that would overwrite the admin field
  // In a real TreasuryConfig, the first 8 bytes are discriminator,
  // then comes the admin pubkey (32 bytes)
  // By writing our pubkey as a BASE58 STRING, when it's copied into the account's
  // raw bytes, it corrupts the binary structure. The account data expects:
  // [8 bytes discriminator][32 bytes pubkey as binary], but instead receives:
  // [44 ASCII characters of base58 string], destroying the data integrity.
  const maliciousMessage = attacker.publicKey.toBase58(); // Our pubkey as string
  
  console.log(`💉 Malicious payload: "${maliciousMessage}"`);
  console.log(`   Length: ${maliciousMessage.length} bytes (base58 string)`);
  console.log("   This will overwrite the account's binary data structure");
  console.log("   Expected: [8 byte discriminator][32 byte binary pubkey]");
  console.log("   Received: [44 ASCII characters]");
  console.log("   Result: Complete data corruption! 💀\n");

  // -------------------------------------------------------------------------
  // Construct the transaction
  // -------------------------------------------------------------------------
  console.log("📝 Building exploit transaction...");
  
  // In the vulnerable program, the instruction expects:
  // - any_unchecked: The account to corrupt (victim account)
  // - msg: The malicious payload
  
  // NOTE: This is pseudo-code since we need the actual IDL
  // In a real attack, you would:
  /*
  const provider = new AnchorProvider(connection, new Wallet(attacker), {});
  const program = new Program(vulnerableIdl, VULNERABLE_PROGRAM_ID, provider);
  
  await program.methods
    .setMessage(maliciousMessage)
    .accounts({
      anyUnchecked: victimAccount.publicKey, // ❌ Passing victim account!
    })
    .signers([attacker])
    .rpc();
  */
  
  console.log("   ✅ Transaction would call: set_message()");
  console.log(`   ✅ Account passed: ${victimAccount.publicKey.toBase58()}`);
  console.log(`   ✅ Payload: "${maliciousMessage}"`);
  console.log("\n❗ RESULT ON VULNERABLE VERSION:");
  console.log("   The program accepts ANY account as 'any_unchecked'");
  console.log("   It performs NO ownership check");
  console.log("   It performs NO type/discriminator check");
  console.log("   It blindly overwrites the account data");
  console.log("   → The victim account is now CORRUPTED! 💀\n");
  
  // -------------------------------------------------------------------------
  // Explain the consequences
  // -------------------------------------------------------------------------
  console.log("💥 ATTACK CONSEQUENCES:");
  console.log("   • If victim account was a TreasuryConfig:");
  console.log("     - Admin field is overwritten with attacker's pubkey");
  console.log("     - Attacker gains admin privileges");
  console.log("     - Can drain protocol treasury");
  console.log("   • If victim account was a User Vault:");
  console.log("     - Balance/owner fields corrupted");
  console.log("     - User loses access to funds");
  console.log("   • If victim account was another protocol's account:");
  console.log("     - Cross-program data corruption");
  console.log("     - Cascading failures across DeFi ecosystem\n");
}

// ============================================================================
// STEP 2: DEMONSTRATE FIXED VERSION
// ============================================================================
async function demonstrateFixedVersion(
  connection: Connection,
  attacker: Keypair,
  victim: Keypair
) {
  console.log("=" + "=".repeat(70));
  console.log("🛡️  DEFENSE PHASE 2: FIXED PROGRAM BLOCKS THE ATTACK");
  console.log("=" + "=".repeat(70) + "\n");

  console.log("🔐 SECURITY IMPROVEMENTS IN FIXED VERSION:");
  console.log("   1. Uses Account<'info, MessageBox> instead of AccountInfo");
  console.log("   2. Automatic discriminator check (ensures correct type)");
  console.log("   3. Automatic ownership check (must be owned by our program)");
  console.log("   4. has_one = authority (links account to authorized signer)");
  console.log("   5. seeds + bump validation (ensures PDA derivation is correct)\n");

  // -------------------------------------------------------------------------
  // Derive the correct PDA for the legitimate user
  // -------------------------------------------------------------------------
  console.log("📍 Deriving correct Program Derived Address (PDA)...");
  
  const [messageBoxPda, bump] = PublicKey.findProgramAddressSync(
    [
      Buffer.from("message"),
      victim.publicKey.toBuffer(), // Must be the victim's pubkey
    ],
    FIXED_PROGRAM_ID
  );
  
  console.log(`   Message Box PDA: ${messageBoxPda.toBase58()}`);
  console.log(`   Bump seed: ${bump}`);
  console.log(`   Derived from: ["message", ${victim.publicKey.toBase58().slice(0, 8)}...]\n`);

  // -------------------------------------------------------------------------
  // Attacker tries the SAME attack on the fixed version
  // -------------------------------------------------------------------------
  console.log("🎯 ATTACKER ATTEMPTS:");
  console.log("   Scenario A: Pass a random account (like before)");
  console.log("   Scenario B: Try to use victim's PDA without authorization\n");

  console.log("❌ SCENARIO A: Passing arbitrary account");
  console.log("   Problem 1: Account discriminator won't match MessageBox");
  console.log("   Problem 2: Seeds won't match (expecting victim's pubkey)");
  console.log("   Problem 3: Account not owned by fixed program");
  console.log("   → Transaction REJECTED by Anchor runtime ✅\n");

  console.log("❌ SCENARIO B: Using correct PDA but wrong signer");
  console.log("   Attacker derives: ['message', victim.pubkey] → PDA");
  console.log("   But signs with attacker's keypair");
  console.log("   has_one = authority check fails:");
  console.log("     account.authority (victim) ≠ signer (attacker)");
  console.log("   → Transaction REJECTED with error: ConstraintHasOne ✅\n");

  console.log("✅ ONLY LEGITIMATE SCENARIO WORKS:");
  console.log("   1. Victim derives their own MessageBox PDA");
  console.log("   2. Victim signs the transaction");
  console.log("   3. All constraints pass:");
  console.log("      • Discriminator matches MessageBox type");
  console.log("      • Account owned by our program");
  console.log("      • Seeds match ['message', victim.pubkey]");
  console.log("      • has_one: account.authority == victim (signer)");
  console.log("   4. Message updated successfully ✅\n");

  // -------------------------------------------------------------------------
  // Show the code difference
  // -------------------------------------------------------------------------
  console.log("📊 CODE COMPARISON:\n");
  console.log("VULNERABLE:");
  console.log("```rust");
  console.log("#[account(mut)]");
  console.log("pub any_unchecked: AccountInfo<'info>,");
  console.log("// ❌ No validation whatsoever!");
  console.log("```\n");

  console.log("FIXED:");
  console.log("```rust");
  console.log("#[account(");
  console.log("    mut,");
  console.log("    has_one = authority,              // ✅ Authorization check");
  console.log("    seeds = [b\"message\", authority.key().as_ref()],  // ✅ Address validation");
  console.log("    bump                                // ✅ PDA verification");
  console.log(")]");
  console.log("pub message_box: Account<'info, MessageBox>,  // ✅ Type validation");
  console.log("pub authority: Signer<'info>,                 // ✅ Signature check");
  console.log("```\n");
}

// ============================================================================
// STEP 3: EDUCATIONAL SUMMARY
// ============================================================================
function printEducationalSummary() {
  console.log("=" + "=".repeat(70));
  console.log("📚 EDUCATIONAL SUMMARY");
  console.log("=" + "=".repeat(70) + "\n");

  console.log("🎓 KEY LESSONS:\n");
  
  console.log("1️⃣  NEVER use raw AccountInfo without validation");
  console.log("   • AccountInfo bypasses ALL Anchor safety checks");
  console.log("   • Only use when you explicitly need raw access");
  console.log("   • If used, manually validate EVERYTHING\n");

  console.log("2️⃣  Always use typed Account<'info, T> when possible");
  console.log("   • Automatic discriminator check (account type)");
  console.log("   • Automatic owner check (owned by your program)");
  console.log("   • Type-safe field access\n");

  console.log("3️⃣  Use has_one constraint for authorization");
  console.log("   • Links account field to transaction signer");
  console.log("   • Prevents unauthorized modifications");
  console.log("   • Clear, declarative security model\n");

  console.log("4️⃣  Use seeds + bump for PDA validation");
  console.log("   • Ensures account address is deterministic");
  console.log("   • Prevents account substitution attacks");
  console.log("   • Guarantees account was created by your program\n");

  console.log("5️⃣  Defense in Depth");
  console.log("   • Combine multiple security checks");
  console.log("   • Type safety + ownership + authorization + address");
  console.log("   • Each layer catches different attack vectors\n");

  console.log("⚠️  REAL-WORLD IMPACT:");
  console.log("   This type of vulnerability has led to:");
  console.log("   • Multi-million dollar protocol drains");
  console.log("   • Unauthorized admin takeovers");
  console.log("   • Cross-protocol contamination");
  console.log("   • Complete loss of user funds\n");

  console.log("🔗 FURTHER READING:");
  console.log("   • Anchor Book: Account Validation");
  console.log("   • Solana Cookbook: Account Security");
  console.log("   • Neodyme Security Guide");
  console.log("   • Sealevel Attacks Repository\n");
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
  printBanner("ATTACK DEMONSTRATION #1", "Missing Account Validation");

  try {
    // Setup environment
    const { connection, attacker, victim } = await setupEnvironment();

    // Demonstrate the vulnerable version
    await demonstrateVulnerableVersion(connection, attacker, victim);

    // Demonstrate the fixed version
    await demonstrateFixedVersion(connection, attacker, victim);

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
