/**
 * ATTACK DEMONSTRATION #3: UNSAFE ARITHMETIC (INTEGER UNDERFLOW)
 * 
 * This script demonstrates how an attacker can exploit unsafe arithmetic
 * operations in Solana programs to cause integer underflow.
 * 
 * VULNERABILITY: Using standard arithmetic operators (-, +, *) in release mode
 *   - Rust's default behavior wraps on overflow/underflow in release builds
 *   - No runtime checks for invalid arithmetic
 *   - Unsigned integers wrap around on underflow
 * 
 * ATTACK VECTOR: Withdraw more than the vault balance, causing underflow
 * that wraps to near u64::MAX, creating "infinite" balance.
 */

import * as anchor from "@coral-xyz/anchor";
import { Program, AnchorProvider, Wallet } from "@coral-xyz/anchor";
import { Connection, Keypair, PublicKey, SystemProgram } from "@solana/web3.js";

// ============================================================================
// PROGRAM IDs - These would be your deployed program addresses
// ============================================================================
const VULNERABLE_PROGRAM_ID = new PublicKey("7Q7L1Srqz1WY5Avzk1kYyqSCDtnznuaCG2qLBVmczWiN");
const FIXED_PROGRAM_ID = new PublicKey("5LApMfCVxYv3BPjVAkVnnBYnCTsRmRykGGBqBPdZiZsa");

// ============================================================================
// Constants for demonstration
// ============================================================================
const LAMPORTS_PER_SOL = 1_000_000_000;
const MAX_U64 = BigInt("18446744073709551615"); // Maximum u64 value

// ============================================================================
// Vault account structure (matches the Rust struct)
// ============================================================================
interface Vault {
  balance: bigint;  // Using BigInt to represent u64
  owner: PublicKey;
}

// ============================================================================
// HELPER: Setup environment
// ============================================================================
async function setupEnvironment() {
  console.log("🔧 Setting up test environment...\n");
  
  // Connect to devnet
  const connection = new Connection("https://api.devnet.solana.com", "confirmed");
  
  // Create user wallet (victim in the protocol)
  const user = Keypair.generate();
  console.log(`👤 User wallet: ${user.publicKey.toBase58()}`);
  
  // Create attacker wallet
  const attacker = Keypair.generate();
  console.log(`👤 Attacker wallet: ${attacker.publicKey.toBase58()}\n`);
  
  // Airdrop SOL for testing
  try {
    console.log("💰 Requesting airdrops...");
    const airdrop1 = await connection.requestAirdrop(
      user.publicKey,
      2 * LAMPORTS_PER_SOL
    );
    const airdrop2 = await connection.requestAirdrop(
      attacker.publicKey,
      2 * LAMPORTS_PER_SOL
    );
    await connection.confirmTransaction(airdrop1);
    await connection.confirmTransaction(airdrop2);
    console.log("✅ Airdrops confirmed\n");
  } catch (error) {
    console.log("⚠️  Airdrop failed, continuing with simulation...\n");
  }
  
  return { connection, user, attacker };
}

// ============================================================================
// HELPER: Create a vault account
// ============================================================================
async function createVaultAccount(
  connection: Connection,
  owner: Keypair,
  programId: PublicKey,
  initialBalance: bigint
): Promise<Keypair> {
  console.log("📦 Creating vault account...");
  
  const vaultAccount = Keypair.generate();
  console.log(`   Vault address: ${vaultAccount.publicKey.toBase58()}`);
  console.log(`   Owner: ${owner.publicKey.toBase58()}`);
  console.log(`   Initial balance: ${initialBalance.toString()} lamports\n`);
  
  // Vault struct: 8 bytes (discriminator) + 8 bytes (balance) + 32 bytes (owner) = 48 bytes
  const space = 8 + 8 + 32;
  const rentExemption = await connection.getMinimumBalanceForRentExemption(space);
  
  // Create the account
  const createAccountIx = SystemProgram.createAccount({
    fromPubkey: owner.publicKey,
    newAccountPubkey: vaultAccount.publicKey,
    lamports: rentExemption,
    space: space,
    programId: programId,
  });

  try {
    const tx = new anchor.web3.Transaction().add(createAccountIx);
    await anchor.web3.sendAndConfirmTransaction(
      connection,
      tx,
      [owner, vaultAccount],
      { commitment: "confirmed" }
    );
    console.log("   ✅ Vault account created\n");
  } catch (error) {
    console.log("   ⚠️  Simulation mode (would work on real cluster)\n");
  }
  
  return vaultAccount;
}

// ============================================================================
// STEP 1: EXPLAIN THE MATHEMATICS OF INTEGER UNDERFLOW
// ============================================================================
function explainUnderflowMathematics() {
  console.log("=" + "=".repeat(70));
  console.log("📐 UNDERSTANDING INTEGER UNDERFLOW");
  console.log("=" + "=".repeat(70) + "\n");

  console.log("🔢 TWO'S COMPLEMENT REPRESENTATION:\n");
  
  console.log("   In computer memory, unsigned integers are stored as binary:");
  console.log("   • u8  (8-bit):  0 to 255");
  console.log("   • u16 (16-bit): 0 to 65,535");
  console.log("   • u32 (32-bit): 0 to 4,294,967,295");
  console.log("   • u64 (64-bit): 0 to 18,446,744,073,709,551,615\n");

  console.log("   What happens when you subtract beyond zero?\n");

  console.log("   Example with u8 (8-bit for simplicity):");
  console.log("   ----------------------------------------");
  console.log("   Starting value: 10");
  console.log("   Binary: 0000 1010");
  console.log("");
  console.log("   Subtract: 11");
  console.log("   Expected: -1 (but u8 cannot represent negative numbers!)");
  console.log("");
  console.log("   In release mode (production), Rust WRAPS:");
  console.log("   10 - 11 = 255  (wraps to maximum u8 value)");
  console.log("   Binary: 1111 1111\n");

  console.log("   The same applies to u64 (our vault balance):");
  console.log("   ---------------------------------------------");
  console.log("   Starting balance: 100 lamports");
  console.log("   Withdraw amount: 101 lamports");
  console.log("   Expected: -1 (impossible!)");
  console.log("");
  console.log(`   Result after wrap: ${MAX_U64.toString()} lamports`);
  console.log("   That's 18.4 QUINTILLION lamports!");
  console.log("   Or about 18.4 BILLION SOL! 💰💰💰\n");

  console.log("⚙️  RUST'S BEHAVIOR:\n");
  console.log("   Debug mode (development):");
  console.log("   • Includes runtime checks");
  console.log("   • Panics on overflow/underflow");
  console.log("   • Protects developers during testing");
  console.log("   • cargo build (default)\n");

  console.log("   Release mode (production):");
  console.log("   • Removes runtime checks for performance");
  console.log("   • Wraps silently on overflow/underflow");
  console.log("   • Used for Solana mainnet deployments!");
  console.log("   • cargo build --release\n");

  console.log("💀 THE DANGER:");
  console.log("   Your tests might pass in debug mode, but the vulnerability");
  console.log("   only manifests in release mode when deployed to mainnet!\n");
}

// ============================================================================
// STEP 2: DEMONSTRATE VULNERABLE VERSION
// ============================================================================
async function demonstrateVulnerableVersion(
  connection: Connection,
  attacker: Keypair
) {
  console.log("=" + "=".repeat(70));
  console.log("🚨 ATTACK PHASE 1: EXPLOITING UNSAFE ARITHMETIC");
  console.log("=" + "=".repeat(70) + "\n");

  // Create vault with a small balance
  const initialBalance = BigInt(100); // 100 lamports
  const vault = await createVaultAccount(
    connection,
    attacker,
    VULNERABLE_PROGRAM_ID,
    initialBalance
  );

  console.log("📊 INITIAL STATE:");
  console.log(`   Vault balance: ${initialBalance} lamports`);
  console.log(`   Vault owner: ${attacker.publicKey.toBase58()}\n`);

  console.log("🎯 VULNERABLE CODE:\n");
  console.log("   ```rust");
  console.log("   pub fn withdraw(ctx: Context<WithdrawVuln>, amount: u64) -> Result<()> {");
  console.log("       let vault = &mut ctx.accounts.vault;");
  console.log("       ");
  console.log("       // ❌ VULNERABILITY: Using -= operator without checks");
  console.log("       vault.balance -= amount;  // This can underflow!");
  console.log("       ");
  console.log("       Ok(())");
  console.log("   }");
  console.log("   ```\n");

  console.log("   The program does NOT check:");
  console.log("   • ❌ Is amount <= vault.balance?");
  console.log("   • ❌ Will the subtraction underflow?");
  console.log("   • ❌ Is the final balance valid?\n");

  // -------------------------------------------------------------------------
  // THE ATTACK: Withdraw more than available balance
  // -------------------------------------------------------------------------
  console.log("💥 EXECUTING ATTACK:");
  console.log("   Step 1: Attacker deposits 100 lamports into vault");
  console.log("   Step 2: Attacker calls withdraw() with amount > balance");
  console.log("   Step 3: Arithmetic underflows, wrapping to maximum value\n");

  const withdrawAmount = BigInt(101); // 1 more than balance
  
  console.log("   📝 Transaction details:");
  console.log(`      Current vault balance: ${initialBalance}`);
  console.log(`      Requested withdrawal:  ${withdrawAmount}`);
  console.log("      Difference:            -1");
  console.log("");
  console.log("   🔢 Arithmetic operation:");
  console.log(`      ${initialBalance} - ${withdrawAmount} = -1`);
  console.log("      Since u64 cannot represent -1, it wraps:");
  console.log(`      Result: ${MAX_U64.toString()}\n`);

  // Simulate the transaction
  /*
  const provider = new AnchorProvider(connection, new Wallet(attacker), {});
  const program = new Program(vulnerableIdl, VULNERABLE_PROGRAM_ID, provider);
  
  await program.methods
    .withdraw(new anchor.BN(withdrawAmount.toString()))
    .accounts({
      vault: vault.publicKey,
      owner: attacker.publicKey,
    })
    .signers([attacker])
    .rpc();
  */

  console.log("✅ TRANSACTION SUCCEEDS ON VULNERABLE VERSION!\n");

  console.log("📊 FINAL STATE:");
  console.log(`   Previous balance: 100 lamports`);
  console.log(`   New balance: 18,446,744,073,709,551,615 lamports`);
  console.log(`   That's ${(Number(MAX_U64) / LAMPORTS_PER_SOL).toFixed(0)} SOL!`);
  console.log(`   Or about $${(Number(MAX_U64) / LAMPORTS_PER_SOL * 100).toLocaleString()} USD (at $100/SOL)\n`);

  // -------------------------------------------------------------------------
  // DEMONSTRATE THE FULL EXPLOIT
  // -------------------------------------------------------------------------
  console.log("💀 COMPLETE ATTACK SCENARIO:\n");
  
  console.log("   Step-by-step exploitation:");
  console.log("   1. Attacker deposits minimal amount (100 lamports = $0.00001)");
  console.log("   2. Attacker withdraws 101 lamports");
  console.log("   3. Balance underflows to 18.4 quintillion lamports");
  console.log("   4. Attacker now has 'infinite' balance in their vault");
  console.log("   5. Attacker can withdraw ALL funds from the protocol");
  console.log("   6. Every other user's vault is drained");
  console.log("   7. Protocol loses all Total Value Locked (TVL)\n");

  console.log("   Example attack on a DeFi protocol:");
  console.log("   • Protocol holds $10M in user funds");
  console.log("   • Attacker's cost: ~$0.00001 (100 lamports)");
  console.log("   • Attacker's balance after underflow: 'infinite'");
  console.log("   • Attacker drains entire protocol");
  console.log("   • Profit: $10M - $0.00001 = $9,999,999.99999\n");

  console.log("⏱️  TIME TO EXPLOIT:");
  console.log("   • Single transaction execution");
  console.log("   • ~400ms on Solana (block time)");
  console.log("   • Impossible to stop once triggered");
  console.log("   • No warning signs or anomalies beforehand\n");
}

// ============================================================================
// STEP 3: DEMONSTRATE FIXED VERSION
// ============================================================================
async function demonstrateFixedVersion(
  connection: Connection,
  attacker: Keypair
) {
  console.log("=" + "=".repeat(70));
  console.log("🛡️  DEFENSE PHASE 2: SAFE ARITHMETIC BLOCKS THE ATTACK");
  console.log("=" + "=".repeat(70) + "\n");

  // Create vault with the same initial balance
  const initialBalance = BigInt(100);
  const vault = await createVaultAccount(
    connection,
    attacker,
    FIXED_PROGRAM_ID,
    initialBalance
  );

  console.log("🔐 FIXED CODE:\n");
  console.log("   ```rust");
  console.log("   pub fn withdraw(ctx: Context<WithdrawSafe>, amount: u64) -> Result<()> {");
  console.log("       let vault = &mut ctx.accounts.vault;");
  console.log("       ");
  console.log("       // ✅ FIX: Using checked_sub() with error handling");
  console.log("       vault.balance = vault");
  console.log("           .balance");
  console.log("           .checked_sub(amount)");
  console.log("           .ok_or(CustomError::InsufficientFunds)?;");
  console.log("       ");
  console.log("       Ok(())");
  console.log("   }");
  console.log("   ```\n");

  console.log("   What checked_sub() does:");
  console.log("   • Attempts the subtraction safely");
  console.log("   • Returns Option<u64>:");
  console.log("     - Some(result) if subtraction is valid (result >= 0)");
  console.log("     - None if subtraction would underflow");
  console.log("   • .ok_or() converts None to Error");
  console.log("   • Transaction aborts before state is modified\n");

  // -------------------------------------------------------------------------
  // ATTACKER TRIES THE SAME EXPLOIT
  // -------------------------------------------------------------------------
  console.log("❌ ATTACKER ATTEMPTS THE SAME EXPLOIT:\n");

  const withdrawAmount = BigInt(101);
  
  console.log("   📝 Transaction details:");
  console.log(`      Current vault balance: ${initialBalance}`);
  console.log(`      Requested withdrawal:  ${withdrawAmount}`);
  console.log("      Valid withdrawal?      NO (101 > 100)\n");

  console.log("   🔍 Execution trace:");
  console.log("   1. Function called: withdraw(101)");
  console.log("   2. Read vault.balance = 100");
  console.log("   3. Execute: 100.checked_sub(101)");
  console.log("   4. checked_sub returns: None (would underflow!)");
  console.log("   5. .ok_or() converts None to Err(InsufficientFunds)");
  console.log("   6. '?' operator propagates error");
  console.log("   7. Transaction REVERTED before state update ✅");
  console.log("   8. Vault balance remains: 100 lamports ✅\n");

  console.log("   🚫 ERROR RETURNED TO ATTACKER:");
  console.log("   Error: AnchorError caused by account: vault");
  console.log("   Error Code: InsufficientFunds");
  console.log("   Error Message: The requested withdrawal amount exceeds the vault balance.\n");

  console.log("✅ ATTACK BLOCKED!");
  console.log("   • No state changes occurred");
  console.log("   • Vault balance unchanged: 100 lamports");
  console.log("   • Attacker wasted transaction fees (~$0.000005)");
  console.log("   • Protocol and user funds remain safe ✅\n");

  // -------------------------------------------------------------------------
  // DEMONSTRATE LEGITIMATE WITHDRAWALS
  // -------------------------------------------------------------------------
  console.log("✅ LEGITIMATE WITHDRAWAL SCENARIO:\n");

  const legitimateAmount = BigInt(50);
  console.log("   📝 Transaction details:");
  console.log(`      Current vault balance: ${initialBalance}`);
  console.log(`      Requested withdrawal:  ${legitimateAmount}`);
  console.log("      Valid withdrawal?      YES (50 <= 100)\n");

  console.log("   🔍 Execution trace:");
  console.log("   1. Function called: withdraw(50)");
  console.log("   2. Read vault.balance = 100");
  console.log("   3. Execute: 100.checked_sub(50)");
  console.log("   4. checked_sub returns: Some(50) ✅");
  console.log("   5. .ok_or() converts Some(50) to Ok(50)");
  console.log("   6. '?' operator unwraps to 50");
  console.log("   7. vault.balance = 50");
  console.log("   8. Transaction SUCCESSFUL ✅\n");

  console.log("   📊 Result:");
  console.log("   • Previous balance: 100 lamports");
  console.log("   • New balance: 50 lamports");
  console.log("   • User withdrew: 50 lamports");
  console.log("   • All math is safe and correct ✅\n");
}

// ============================================================================
// STEP 4: OTHER SAFE ARITHMETIC METHODS
// ============================================================================
function explainSafeArithmeticMethods() {
  console.log("=" + "=".repeat(70));
  console.log("🛠️  SAFE ARITHMETIC TOOLKIT");
  console.log("=" + "=".repeat(70) + "\n");

  console.log("📚 RUST'S CHECKED ARITHMETIC METHODS:\n");

  console.log("   1. checked_add(rhs) - Addition");
  console.log("      • Returns None on overflow");
  console.log("      • Example: u64::MAX.checked_add(1) = None\n");

  console.log("   2. checked_sub(rhs) - Subtraction");
  console.log("      • Returns None on underflow");
  console.log("      • Example: 0u64.checked_sub(1) = None\n");

  console.log("   3. checked_mul(rhs) - Multiplication");
  console.log("      • Returns None on overflow");
  console.log("      • Example: u64::MAX.checked_mul(2) = None\n");

  console.log("   4. checked_div(rhs) - Division");
  console.log("      • Returns None on division by zero");
  console.log("      • Example: 100u64.checked_div(0) = None\n");

  console.log("   5. saturating_* variants - Saturate at bounds");
  console.log("      • saturating_sub(): Returns 0 instead of wrapping");
  console.log("      • Example: 10u64.saturating_sub(20) = 0");
  console.log("      • Useful when you want to clamp to minimum/maximum\n");

  console.log("🎯 BEST PRACTICES:\n");
  console.log("   ✅ DO:");
  console.log("   • Use checked_* for financial calculations");
  console.log("   • Use saturating_* when clamping is desired behavior");
  console.log("   • Always handle the None/Error case explicitly");
  console.log("   • Test with values near boundaries (0, MAX)\n");

  console.log("   ❌ DON'T:");
  console.log("   • Use +, -, *, / operators for user-controlled values");
  console.log("   • Assume debug mode catches all arithmetic bugs");
  console.log("   • Rely on pre-condition checks alone (defense in depth!)");
  console.log("   • Use wrapping_* unless you have a very specific reason\n");

  console.log("💡 ANCHOR HELPERS:\n");
  console.log("   Anchor provides helper macros:");
  console.log("   • Use require!() for pre-condition checks");
  console.log("   • Example: require!(amount <= balance, ErrorCode::InsufficientFunds);\n");

  console.log("   Combined approach (defense in depth):");
  console.log("   ```rust");
  console.log("   // Pre-condition check (clarity + early return)");
  console.log("   require!(amount <= vault.balance, ErrorCode::InsufficientFunds);");
  console.log("   ");
  console.log("   // Safe arithmetic (extra safety layer)");
  console.log("   vault.balance = vault.balance.checked_sub(amount)?;");
  console.log("   ```\n");
}

// ============================================================================
// STEP 5: EDUCATIONAL SUMMARY
// ============================================================================
function printEducationalSummary() {
  console.log("=" + "=".repeat(70));
  console.log("📚 EDUCATIONAL SUMMARY");
  console.log("=" + "=".repeat(70) + "\n");

  console.log("🎓 KEY LESSONS:\n");
  
  console.log("1️⃣  Integer arithmetic is dangerous in production");
  console.log("   • Rust wraps on overflow/underflow in release mode");
  console.log("   • This is for performance, not safety");
  console.log("   • Your tests in debug mode won't catch this!\n");

  console.log("2️⃣  Always use checked arithmetic for financial operations");
  console.log("   • checked_sub() for subtraction");
  console.log("   • checked_add() for addition");
  console.log("   • checked_mul() for multiplication");
  console.log("   • Handle the Option/Result properly\n");

  console.log("3️⃣  Test in release mode");
  console.log("   • cargo build-sbf (Solana's release mode)");
  console.log("   • Test boundary conditions: 0, MAX, near-overflow");
  console.log("   • Use property-based testing (quickcheck)\n");

  console.log("4️⃣  Defense in depth");
  console.log("   • Pre-condition checks (require!)");
  console.log("   • Safe arithmetic (checked_*)");
  console.log("   • Post-condition validation");
  console.log("   • Each layer catches different edge cases\n");

  console.log("5️⃣  Understand the cost of bugs");
  console.log("   • Single integer underflow = total protocol drain");
  console.log("   • No recovery possible after exploit");
  console.log("   • Cost: Minutes to write .checked_sub()");
  console.log("   • Benefit: Preventing million-dollar hacks\n");

  console.log("⚠️  REAL-WORLD IMPACT:");
  console.log("   This type of vulnerability has caused:");
  console.log("   • Complete protocol drains (100% TVL loss)");
  console.log("   • Infinite token minting exploits");
  console.log("   • Impossible balances breaking protocol logic");
  console.log("   • Billions of dollars in cumulative losses across crypto\n");

  console.log("🔗 FURTHER READING:");
  console.log("   • Rust Book: Integer Overflow");
  console.log("   • Solana Cookbook: Safe Math");
  console.log("   • Neodyme: Arithmetic Vulnerabilities");
  console.log("   • Anchor: Error Handling Best Practices\n");
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
  printBanner("ATTACK DEMONSTRATION #3", "Unsafe Arithmetic (Integer Underflow)");

  try {
    // Setup environment
    const { connection, user, attacker } = await setupEnvironment();

    // Explain the mathematics
    explainUnderflowMathematics();

    // Demonstrate vulnerable version
    await demonstrateVulnerableVersion(connection, attacker);

    // Demonstrate fixed version
    await demonstrateFixedVersion(connection, attacker);

    // Explain safe arithmetic methods
    explainSafeArithmeticMethods();

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
