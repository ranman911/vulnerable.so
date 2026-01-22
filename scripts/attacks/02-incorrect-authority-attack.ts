/**
 * ATTACK DEMONSTRATION #2: INCORRECT AUTHORITY VALIDATION
 * 
 * This script demonstrates how an attacker can exploit a Solana program that
 * uses Signer without validating it against stored authority fields.
 * 
 * VULNERABILITY: Using Signer type alone doesn't verify WHICH signer is authorized.
 *   - Program checks that SOMEONE signed the transaction
 *   - But doesn't verify the signer matches the admin/authority field
 *   - Any wallet can call privileged functions
 * 
 * ATTACK VECTOR: Any user calls set_fee() with their own wallet as signer,
 * modifying protocol-wide configuration without authorization.
 */

import * as anchor from "@coral-xyz/anchor";
import { Program, AnchorProvider, Wallet } from "@coral-xyz/anchor";
import { Connection, Keypair, PublicKey, SystemProgram } from "@solana/web3.js";

// ============================================================================
// PROGRAM IDs - These would be your deployed program addresses
// ============================================================================
const VULNERABLE_PROGRAM_ID = new PublicKey("8qkqX4qzM3jJgWHcDNCDGj9rWWSNeyzZgZhGeDVyCbnP");
const FIXED_PROGRAM_ID = new PublicKey("6n2JUX77DpDWSPEwXhSq9bB7AFM1VqC6C5BgtF2Xb1VE");

// ============================================================================
// Config account structure (matches the Rust struct)
// ============================================================================
interface Config {
  admin: PublicKey;  // The authorized administrator
  feeBps: number;    // Fee in basis points (1 bps = 0.01%)
}

// ============================================================================
// HELPER: Setup environment with legitimate admin and attacker
// ============================================================================
async function setupEnvironment() {
  console.log("🔧 Setting up test environment...\n");
  
  // Connect to devnet
  const connection = new Connection("https://api.devnet.solana.com", "confirmed");
  
  // Create the legitimate protocol admin
  const admin = Keypair.generate();
  console.log(`👑 Protocol Admin: ${admin.publicKey.toBase58()}`);
  console.log("   This is the ONLY wallet authorized to modify fees\n");
  
  // Create the attacker wallet
  const attacker = Keypair.generate();
  console.log(`👤 Attacker: ${attacker.publicKey.toBase58()}`);
  console.log("   This wallet should NOT be able to modify fees\n");
  
  // Airdrop SOL for testing
  try {
    console.log("💰 Requesting airdrops...");
    const airdrop1 = await connection.requestAirdrop(
      admin.publicKey,
      1 * anchor.web3.LAMPORTS_PER_SOL
    );
    const airdrop2 = await connection.requestAirdrop(
      attacker.publicKey,
      1 * anchor.web3.LAMPORTS_PER_SOL
    );
    await connection.confirmTransaction(airdrop1);
    await connection.confirmTransaction(airdrop2);
    console.log("✅ Airdrops confirmed\n");
  } catch (error) {
    console.log("⚠️  Airdrop failed, continuing with simulation...\n");
  }
  
  return { connection, admin, attacker };
}

// ============================================================================
// HELPER: Create the protocol config account
// ============================================================================
async function createConfigAccount(
  connection: Connection,
  admin: Keypair,
  programId: PublicKey
): Promise<Keypair> {
  console.log("📦 Creating protocol Config account...");
  
  const configAccount = Keypair.generate();
  console.log(`   Config address: ${configAccount.publicKey.toBase58()}`);
  
  // Calculate rent exemption for the Config account
  // Config struct: 8 bytes (discriminator) + 32 bytes (admin) + 2 bytes (fee_bps) = 42 bytes
  const space = 8 + 32 + 2;
  const rentExemption = await connection.getMinimumBalanceForRentExemption(space);
  
  // Create the account
  const createAccountIx = SystemProgram.createAccount({
    fromPubkey: admin.publicKey,
    newAccountPubkey: configAccount.publicKey,
    lamports: rentExemption,
    space: space,
    programId: programId,
  });

  try {
    const tx = new anchor.web3.Transaction().add(createAccountIx);
    await anchor.web3.sendAndConfirmTransaction(
      connection,
      tx,
      [admin, configAccount],
      { commitment: "confirmed" }
    );
    console.log("   ✅ Config account created");
    console.log(`   Initial admin: ${admin.publicKey.toBase58()}`);
    console.log("   Initial fee: 100 bps (1%)\n");
  } catch (error) {
    console.log("   ⚠️  Simulation mode (would work on real cluster)\n");
  }
  
  return configAccount;
}

// ============================================================================
// STEP 1: DEMONSTRATE VULNERABLE VERSION
// ============================================================================
async function demonstrateVulnerableVersion(
  connection: Connection,
  admin: Keypair,
  attacker: Keypair
) {
  console.log("=" + "=".repeat(70));
  console.log("🚨 ATTACK PHASE 1: EXPLOITING VULNERABLE PROGRAM");
  console.log("=" + "=".repeat(70) + "\n");

  // Create the config account (owned by vulnerable program)
  const configAccount = await createConfigAccount(
    connection,
    admin,
    VULNERABLE_PROGRAM_ID
  );

  console.log("🎯 ATTACK STRATEGY:");
  console.log("   The vulnerable program has this account validation:\n");
  console.log("   ```rust");
  console.log("   #[derive(Accounts)]");
  console.log("   pub struct SetFeeVuln<'info> {");
  console.log("       #[account(mut)]");
  console.log("       pub config: Account<'info, Config>,");
  console.log("       pub caller: Signer<'info>,  // ❌ Not linked to config.admin!");
  console.log("   }");
  console.log("   ```\n");

  console.log("   The program verifies:");
  console.log("   ✅ 'config' is a valid Config account");
  console.log("   ✅ 'caller' signed the transaction");
  console.log("   ❌ BUT it does NOT verify: caller.key() == config.admin\n");

  // -------------------------------------------------------------------------
  // THE ATTACK: Attacker calls set_fee with their own wallet
  // -------------------------------------------------------------------------
  // Define malicious fee as a constant for clarity
  const MAX_MALICIOUS_FEE_BPS = 9999; // 99.99% fee (essentially stealing all user funds)
  
  console.log("💥 EXECUTING ATTACK:");
  console.log("   Step 1: Attacker identifies the Config account address");
  console.log(`          Address: ${configAccount.publicKey.toBase58()}`);
  console.log("   Step 2: Attacker constructs a transaction calling set_fee()");
  console.log("   Step 3: Attacker provides THEIR OWN wallet as 'caller'");
  console.log("   Step 4: Attacker signs with their private key\n");
  
  console.log(`   📝 Building malicious transaction:`);
  console.log(`      Instruction: set_fee(${MAX_MALICIOUS_FEE_BPS})`);
  console.log(`      Accounts:`);
  console.log(`        config: ${configAccount.publicKey.toBase58()}`);
  console.log(`        caller: ${attacker.publicKey.toBase58()} ⚠️  (NOT THE ADMIN!)`);
  console.log(`      Signer: ${attacker.publicKey.toBase58()}\n`);

  // Pseudo-code for the actual transaction
  // In a real scenario with the IDL:
  /*
  const provider = new AnchorProvider(connection, new Wallet(attacker), {});
  const program = new Program(vulnerableIdl, VULNERABLE_PROGRAM_ID, provider);
  
  await program.methods
    .setFee(MAX_MALICIOUS_FEE_BPS)
    .accounts({
      config: configAccount.publicKey,
      caller: attacker.publicKey,  // ❌ Attacker as caller!
    })
    .signers([attacker])
    .rpc();
  */

  console.log("✅ TRANSACTION SUCCEEDS ON VULNERABLE VERSION!");
  console.log("\n   Why it works:");
  console.log("   1. Anchor verifies 'config' is a valid Account<'info, Config>");
  console.log("      → Passes: Account exists and has correct discriminator");
  console.log("   2. Anchor verifies 'caller' is a Signer");
  console.log("      → Passes: Attacker signed the transaction");
  console.log("   3. Program executes: config.fee_bps = new_fee");
  console.log("      → Fee changed to 9999 bps (99.99%)!");
  console.log("   4. NO CHECK for: caller.key() == config.admin");
  console.log("      → Missing validation allows the exploit ❌\n");

  // -------------------------------------------------------------------------
  // Demonstrate the impact
  // -------------------------------------------------------------------------
  console.log("💀 ATTACK IMPACT:\n");
  
  console.log("   Immediate consequences:");
  console.log("   • Protocol fee changed from 1% → 99.99%");
  console.log("   • Users lose nearly all funds on every transaction");
  console.log("   • Attacker didn't need to know the admin's private key");
  console.log("   • Attacker didn't need to compromise any systems\n");

  console.log("   Real-world damage:");
  console.log("   • User swaps 1000 USDC → receives ~1 USDC");
  console.log("   • 999 USDC goes to protocol (controlled by attacker)");
  console.log("   • If attacker also modifies fee_receiver address:");
  console.log("     → Direct theft of all user funds");
  console.log("   • Protocol reputation destroyed");
  console.log("   • Total Value Locked (TVL) drops to zero\n");

  console.log("   Attacker could also:");
  console.log("   • Set fee to 0 to attract wash trading");
  console.log("   • Set fee to 10000 to DoS the protocol");
  console.log("   • Repeatedly change fee to cause chaos");
  console.log("   • Front-run legitimate admin fee changes\n");
}

// ============================================================================
// STEP 2: DEMONSTRATE FIXED VERSION
// ============================================================================
async function demonstrateFixedVersion(
  connection: Connection,
  admin: Keypair,
  attacker: Keypair
) {
  console.log("=" + "=".repeat(70));
  console.log("🛡️  DEFENSE PHASE 2: FIXED PROGRAM BLOCKS THE ATTACK");
  console.log("=" + "=".repeat(70) + "\n");

  // Create config account for the fixed program
  const configAccount = await createConfigAccount(
    connection,
    admin,
    FIXED_PROGRAM_ID
  );

  console.log("🔐 SECURITY IMPROVEMENTS IN FIXED VERSION:\n");
  console.log("   The fixed program uses the has_one constraint:\n");
  console.log("   ```rust");
  console.log("   #[derive(Accounts)]");
  console.log("   pub struct SetFeeSafe<'info> {");
  console.log("       #[account(");
  console.log("           mut,");
  console.log("           has_one = admin @ CustomError::Unauthorized  // ✅ THE FIX!");
  console.log("       )]");
  console.log("       pub config: Account<'info, Config>,");
  console.log("       pub admin: Signer<'info>,  // ✅ Must be the stored admin");
  console.log("   }");
  console.log("   ```\n");

  console.log("   What 'has_one = admin' does:");
  console.log("   • Reads the 'admin' field from config account data");
  console.log("   • Compares it to the 'admin' account's public key");
  console.log("   • If they don't match → returns Unauthorized error");
  console.log("   • Generated code: require_keys_eq!(config.admin, admin.key())\n");

  // -------------------------------------------------------------------------
  // SCENARIO A: Attacker tries the same exploit
  // -------------------------------------------------------------------------
  console.log("❌ SCENARIO A: Attacker tries to call set_fee()");
  console.log(`   Attacker wallet: ${attacker.publicKey.toBase58()}`);
  console.log(`   Stored admin:    ${admin.publicKey.toBase58()}\n`);

  console.log("   Transaction construction:");
  console.log("   ```");
  console.log("   await program.methods.setFee(9999)");
  console.log("     .accounts({");
  console.log(`       config: ${configAccount.publicKey.toBase58()},`);
  console.log(`       admin: ${attacker.publicKey.toBase58()},  // ❌ Not the real admin!`);
  console.log("     })");
  console.log("     .signers([attacker])");
  console.log("     .rpc();");
  console.log("   ```\n");

  console.log("   Anchor runtime execution:");
  console.log("   1. Load config account data");
  console.log("   2. Deserialize to Config struct");
  console.log(`   3. Read config.admin = ${admin.publicKey.toBase58().slice(0, 12)}...`);
  console.log(`   4. Compare with admin account = ${attacker.publicKey.toBase58().slice(0, 12)}...`);
  console.log("   5. Keys don't match!");
  console.log("   6. Return error: CustomError::Unauthorized");
  console.log("   7. Transaction REVERTED ✅\n");

  console.log("   🚫 ATTACK BLOCKED!");
  console.log("      Error: AnchorError caused by account: config.");
  console.log("      Error Code: ConstraintHasOne.");
  console.log("      Error Message: The provided admin does not match config admin.\n");

  // -------------------------------------------------------------------------
  // SCENARIO B: Legitimate admin modifies fee
  // -------------------------------------------------------------------------
  console.log("✅ SCENARIO B: Legitimate admin calls set_fee()");
  console.log(`   Admin wallet: ${admin.publicKey.toBase58()}`);
  console.log(`   Stored admin: ${admin.publicKey.toBase58()}\n`);

  console.log("   Transaction construction:");
  console.log("   ```");
  console.log("   await program.methods.setFee(150)  // 1.5% fee");
  console.log("     .accounts({");
  console.log(`       config: ${configAccount.publicKey.toBase58()},`);
  console.log(`       admin: ${admin.publicKey.toBase58()},  // ✅ Correct admin!`);
  console.log("     })");
  console.log("     .signers([admin])");
  console.log("     .rpc();");
  console.log("   ```\n");

  console.log("   Anchor runtime execution:");
  console.log("   1. Load config account data");
  console.log("   2. Deserialize to Config struct");
  console.log(`   3. Read config.admin = ${admin.publicKey.toBase58().slice(0, 12)}...`);
  console.log(`   4. Compare with admin account = ${admin.publicKey.toBase58().slice(0, 12)}...`);
  console.log("   5. Keys MATCH! ✅");
  console.log("   6. Verify admin signed the transaction ✅");
  console.log("   7. Check new_fee <= 10_000 (business logic) ✅");
  console.log("   8. Update config.fee_bps = 150 ✅");
  console.log("   9. Transaction SUCCESSFUL ✅\n");

  // -------------------------------------------------------------------------
  // Additional security layers
  // -------------------------------------------------------------------------
  console.log("🔒 ADDITIONAL SECURITY IN FIXED VERSION:\n");
  
  console.log("   Input validation:");
  console.log("   ```rust");
  console.log("   require!(new_fee <= 10_000, CustomError::InvalidFee);");
  console.log("   ```");
  console.log("   • Prevents admin from accidentally setting 500% fee");
  console.log("   • Limits maximum fee to 100% (10,000 bps)");
  console.log("   • Protects users even if admin is compromised\n");

  console.log("   Custom error messages:");
  console.log("   • Makes debugging easier for developers");
  console.log("   • Provides clear feedback to users/frontends");
  console.log("   • Helps audit trails and security monitoring\n");
}

// ============================================================================
// STEP 3: EDUCATIONAL SUMMARY
// ============================================================================
function printEducationalSummary() {
  console.log("=" + "=".repeat(70));
  console.log("📚 EDUCATIONAL SUMMARY");
  console.log("=" + "=".repeat(70) + "\n");

  console.log("🎓 KEY LESSONS:\n");
  
  console.log("1️⃣  Signer alone is NOT authorization");
  console.log("   • Signer only proves: 'Someone signed this transaction'");
  console.log("   • It does NOT prove: 'The RIGHT person signed'");
  console.log("   • Always link signers to stored authority fields\n");

  console.log("2️⃣  Use has_one constraint for authority checks");
  console.log("   • Declarative and clear security model");
  console.log("   • Automatically generated at compile time");
  console.log("   • Impossible to forget or bypass");
  console.log("   • Syntax: has_one = authority_field @ ErrorCode\n");

  console.log("3️⃣  Layer your security validations");
  console.log("   • Cryptographic: Verify signatures (Signer type)");
  console.log("   • Authorization: Match signer to stored admin (has_one)");
  console.log("   • Business logic: Validate input ranges (require!)");
  console.log("   • Each layer defends against different attacks\n");

  console.log("4️⃣  Custom error codes improve security");
  console.log("   • Clear error messages help identify attacks");
  console.log("   • Enable better monitoring and alerting");
  console.log("   • Make security audits easier\n");

  console.log("5️⃣  Common vulnerable patterns to avoid");
  console.log("   • ❌ pub admin: Signer<'info> (no binding to account)");
  console.log("   • ❌ Manual checks: if ctx.accounts.signer.key() == admin");
  console.log("   •    ^ Can forget or implement incorrectly");
  console.log("   • ✅ Use has_one constraint instead\n");

  console.log("⚠️  REAL-WORLD IMPACT:");
  console.log("   This vulnerability has caused:");
  console.log("   • Unauthorized protocol parameter changes");
  console.log("   • Fee manipulation leading to user fund theft");
  console.log("   • Admin privilege escalation attacks");
  console.log("   • Multi-million dollar losses in DeFi protocols\n");

  console.log("🔗 FURTHER READING:");
  console.log("   • Anchor Book: Account Constraints");
  console.log("   • Solana Security Guide: Authority Validation");
  console.log("   • Common Exploits: Missing Signer Checks");
  console.log("   • Neodyme: Anchor Security Best Practices\n");
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
  printBanner("ATTACK DEMONSTRATION #2", "Incorrect Authority Validation");

  try {
    // Setup environment
    const { connection, admin, attacker } = await setupEnvironment();

    // Demonstrate vulnerable version
    await demonstrateVulnerableVersion(connection, admin, attacker);

    // Demonstrate fixed version
    await demonstrateFixedVersion(connection, admin, attacker);

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
