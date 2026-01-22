# Solana Security Reference: Educational Vulnerability Examples

> **A comprehensive, educational repository demonstrating common Solana security vulnerabilities and their fixes**

[![Anchor](https://img.shields.io/badge/Anchor-0.32.1-blue)](https://www.anchor-lang.com/)
[![Solana](https://img.shields.io/badge/Solana-Latest-purple)](https://solana.com/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![CI Status](https://github.com/CYBWithFlourish/vulnerable.so/workflows/Security%20Testing%20CI/badge.svg)](https://github.com/CYBWithFlourish/vulnerable.so/actions/workflows/ci.yml)
[![Security Audit](https://github.com/CYBWithFlourish/vulnerable.so/workflows/Weekly%20Security%20Audit/badge.svg)](https://github.com/CYBWithFlourish/vulnerable.so/actions/workflows/scheduled-audit.yml)
[![Documentation](https://github.com/CYBWithFlourish/vulnerable.so/workflows/Documentation%20Validation/badge.svg)](https://github.com/CYBWithFlourish/vulnerable.so/actions/workflows/docs.yml)

## Table of Contents

- [Overview](#overview)
- [Vulnerability Categories](#vulnerability-categories)
- [Repository Structure](#repository-structure)
- [Setup Instructions](#setup-instructions)
- [Testing Guide](#testing-guide)
- [Learning Path](#learning-path)
- [Contribution Guidelines](#contribution-guidelines)
- [Resources](#resources)

## Overview

This repository serves as a **security-first educational reference** for developers building on Solana. Each example pairs a **vulnerable implementation** with a **secured version**, complete with detailed explanations of:

- **What** the vulnerability is
- **Why** it's dangerous
- **How** an attack works
- **How** the fix prevents the attack

All code is designed to be **beginner-friendly** yet **technically accurate**, making it ideal for:
- Developers new to Solana security
- Security auditors learning Solana-specific vulnerabilities
- Teams establishing security best practices
- Educational workshops and training programs

**⚠️ Important:** None of these programs should be deployed to production. They are intentionally vulnerable teaching samples.

## Vulnerability Categories

This repository covers **5 critical vulnerability classes** commonly found in Solana programs:

### 1. Missing Account Validation

**Risk Level:** 🔴 Critical

The program accepts raw `AccountInfo` without verifying ownership, type, or expected derivation. Attackers can substitute arbitrary accounts to corrupt state or escalate privileges.

**Key Issues:**
- No owner verification
- Missing discriminator checks
- Lack of PDA seed validation
- No authority binding

📖 [Full Tutorial](examples/01-missing-account-validation/README.md) | 💻 [Vulnerable Code](examples/01-missing-account-validation/example1.rs) | ✅ [Fixed Code](examples/01-missing-account-validation/example1.fix.rs)

### 2. Incorrect Authority Check

**Risk Level:** 🔴 Critical

The program requires a signer but never verifies if that signer is actually authorized to perform the action. Any wallet can modify critical protocol parameters.

**Key Issues:**
- Authentication without authorization
- Missing `has_one` constraints
- No admin verification
- Unbounded parameter changes

📖 [Full Tutorial](examples/02-incorrect-authority-check/README.md) | 💻 [Vulnerable Code](examples/02-incorrect-authority-check/example2.rs) | ✅ [Fixed Code](examples/02-incorrect-authority-check/example2.fix.rs)

### 3. Unsafe Arithmetic

**Risk Level:** 🟠 High

The program uses standard arithmetic operators (`-`, `+`, `*`) without overflow checks. In release mode, overflow wraps silently, leading to balance corruption or infinite minting.

**Key Issues:**
- Integer overflow/underflow
- Silent wrapping in release mode
- Missing bounds validation
- Lack of checked math methods

📖 [Full Tutorial](examples/03-unsafe-arithmetic/README.md) | 💻 [Vulnerable Code](examples/03-unsafe-arithmetic/example3.rs) | ✅ [Fixed Code](examples/03-unsafe-arithmetic/example3.fix.rs)

### 4. CPI Reentrancy

**Risk Level:** 🟠 High

The program calls external programs (CPI) before updating internal state. A malicious external program can re-enter and exploit stale state to drain funds.

**Key Issues:**
- State updates after external calls
- Missing reentrancy guards
- CEI pattern violation
- Lack of locks/flags

📖 [Full Tutorial](examples/04-cpi-reentrancy/README.md) | 💻 [Vulnerable Code](examples/04-cpi-reentrancy/example4.rs) | ✅ [Fixed Code](examples/04-cpi-reentrancy/example4.fix.rs)

### 5. Signer Privilege Escalation

**Risk Level:** 🔴 Critical

The program validates that an account is a signer but doesn't verify that the signer's identity matches an authorized role stored in program state. Any signer can escalate privileges.

**Key Issues:**
- Signer type without identity check
- Missing `has_one` binding
- Privilege validation gap
- Role-based access control failure

📖 [Full Tutorial](examples/05-signer-privilege-escalation/README.md) | 💻 [Vulnerable Code](examples/05-signer-privilege-escalation/example5.rs) | ✅ [Fixed Code](examples/05-signer-privilege-escalation/example5.fix.rs)

## Repository Structure

```
vulnerable.so/
├── README.md                   # This file
├── SECURITY.md                 # Comprehensive security documentation
├── Anchor.toml                 # Anchor workspace configuration
├── Cargo.toml                  # Rust workspace configuration
│
├── docs/
│   └── PINOCCHIO.md           # Pinocchio testing guide
│
├── examples/                   # Side-by-side vulnerable vs. fixed code
│   ├── 01-missing-account-validation/
│   │   ├── README.md          # Full tutorial
│   │   ├── example1.rs        # Vulnerable version
│   │   └── example1.fix.rs    # Fixed version
│   ├── 02-incorrect-authority-check/
│   ├── 03-unsafe-arithmetic/
│   ├── 04-cpi-reentrancy/
│   └── 05-signer-privilege-escalation/
│
├── programs/                   # Full Anchor programs (deployable)
│   ├── 01a-missing-account-validation-vuln/
│   ├── 01b-missing-account-validation-fix/
│   ├── 01c-missing-account-validation-attacker/
│   ├── 02a-incorrect-authority-vuln/
│   ├── 02b-incorrect-authority-fix/
│   ├── 02c-incorrect-authority-attacker/
│   ├── 03a-unsafe-arithmetic-vuln/
│   ├── 03b-unsafe-arithmetic-fix/
│   ├── 03c-unsafe-arithmetic-attacker/
│   ├── 04a-cpi-reentrancy-vuln/
│   ├── 04b-cpi-reentrancy-fix/
│   ├── 04c-cpi-reentrancy-attacker/
│   ├── 05a-signer-privilege-escalation-vuln/
│   ├── 05b-signer-privilege-escalation-fix/
│   └── 05c-signer-privilege-escalation-attacker/
│
└── scripts/
    ├── attacks/               # TypeScript attack demonstrations
    │   ├── 01-missing-account-attack.ts
    │   ├── 02-incorrect-authority-attack.ts
    │   ├── 03-unsafe-arithmetic-attack.ts
    │   └── 05-signer-privilege-attack.ts
    └── cpi-reentrancy.ts     # CPI reentrancy test
```

## Setup Instructions

### Prerequisites

- **Rust** 1.75+ with `cargo` ([Install Rust](https://rustup.rs/))
- **Solana CLI** 1.18+ ([Install Solana](https://docs.solana.com/cli/install-solana-cli-tools))
- **Anchor** 0.32.1 ([Install Anchor](https://www.anchor-lang.com/docs/installation))
- **Node.js** 18+ and **Yarn** (for TypeScript tests)
- **Pinocchio** (optional, for fast testing) ([Install Pinocchio](https://github.com/anza-xyz/pinocchio))

### Installation

1. **Clone the repository:**

```bash
git clone https://github.com/CYBWithFlourish/vulnerable.so.git
cd vulnerable.so
```

2. **Build all programs:**

```bash
anchor build
```

This compiles all 15 programs (5 vulnerabilities × 3 versions each).

3. **Install TypeScript dependencies:**

```bash
yarn install
```

4. **Verify build artifacts:**

```bash
ls -l target/deploy/*.so
ls -l target/idl/*.json
```

### Anchor Configuration

The project uses Anchor's workspace feature to manage multiple programs. Key configuration in `Anchor.toml`:

```toml
[programs.devnet]
cpi-reentrancy-vuln = "4tZXygwa8iqkS7AGGcqWptSzT8PGgQRYM3dAXCuF1rKB"
cpi-reentrancy-fix = "H8sBVtiyV2ZqWsfpZq2R7oKkyN1UQg61ddpxXsD5ouAQ"
cpi-reentrancy-attacker = "2SuAQ3vLxMomnMZP7bAHaHJXU5iyMDyxB2K5TbUnFZWH"
```

Programs are defined in the workspace `Cargo.toml` with shared dependencies:
- `anchor-lang = "0.32.1"`
- `pinocchio = "1.52"`

### Pinocchio Setup

Pinocchio is a fast, lightweight Solana testing library included as a workspace dependency.

1. **Add to your program's `Cargo.toml`:**

```toml
[dependencies]
pinocchio = { workspace = true }
```

2. **Write tests using Pinocchio:**

```rust
#[cfg(test)]
mod tests {
    use pinocchio::*;
    
    #[test]
    fn test_my_instruction() {
        // Your test code
    }
}
```

3. **Run tests:**

```bash
cargo test
```

📖 See [docs/PINOCCHIO.md](docs/PINOCCHIO.md) for complete usage guide and examples.

## Testing Guide

### Method 1: Anchor Tests (Full Validator)

Run the complete test suite with a local validator:

```bash
# Start local validator in background
solana-test-validator &

# Run all tests
anchor test

# Run specific test file
anchor test -- --grep "CPI Reentrancy"
```

**Pros:** Full Solana environment, realistic simulation  
**Cons:** Slow startup (~30 seconds), resource intensive

### Method 2: Pinocchio Library Tests (Fast Simulation)

Test individual programs using Pinocchio as a library dependency:

```bash
# Run all Pinocchio tests
cargo test

# Run tests for a specific program
cargo test --package missing-account-validation-fix

# Run with output
cargo test -- --nocapture
```

**Example Pinocchio Test:**

```rust
#[cfg(test)]
mod tests {
    use pinocchio::pubkey::Pubkey;

    #[test]
    fn test_account_validation() {
        let account = Pubkey::new_unique();
        // Test your validation logic
        println!("Testing with account: {}", account);
    }
}
```

**Pros:** Instant startup, lightweight, fast iteration, integrated with `cargo test`  
**Cons:** Limited runtime features, simplified environment

📖 See [docs/PINOCCHIO.md](docs/PINOCCHIO.md) for detailed examples and the `examples/*/example*.pinocchio.rs` files.

### Method 3: Attack Scripts (TypeScript)

Run the attack demonstration scripts:

```bash
# Missing account substitution attack
ts-node scripts/attacks/01-missing-account-attack.ts

# Incorrect authority attack
ts-node scripts/attacks/02-incorrect-authority-attack.ts

# Unsafe arithmetic underflow attack
ts-node scripts/attacks/03-unsafe-arithmetic-attack.ts

# Signer privilege escalation attack
ts-node scripts/attacks/05-signer-privilege-attack.ts
```

Each script demonstrates:
1. How to construct the malicious transaction
2. Why the vulnerable version accepts it
3. How the attack succeeds
4. Why the fixed version rejects it

## CI/CD & Automated Testing

This repository includes comprehensive GitHub Actions workflows for continuous integration and security testing.

### Automated Workflows

#### 1. Security Testing CI (`.github/workflows/ci.yml`)

Runs on every push and pull request to validate all security demonstrations.

**Jobs:**
- **Build Programs**: Compiles all 15 Solana programs (5 vulnerabilities × 3 versions)
- **Attack Demonstrations**: Runs TypeScript attack scripts for vulnerabilities 01, 02, 03, and 05
- **Rust Unit Tests**: Executes `cargo test-sbf` for all program variants
- **Pinocchio Tests**: Fast simulation testing
- **Security Summary**: Aggregates results and posts PR comments

**Status**: [![CI Status](https://github.com/CYBWithFlourish/vulnerable.so/workflows/Security%20Testing%20CI/badge.svg)](https://github.com/CYBWithFlourish/vulnerable.so/actions/workflows/ci.yml)

#### 2. Weekly Security Audit (`.github/workflows/scheduled-audit.yml`)

Runs every Sunday at midnight UTC to ensure ongoing security.

**Jobs:**
- **Dependency Audit**: Checks for vulnerabilities using `cargo audit` and `npm audit`
- **Version Compatibility**: Tests against latest Solana/Anchor versions
- **Comprehensive Tests**: Full test suite execution
- **Issue Creation**: Automatically opens GitHub issues on failures

**Status**: [![Security Audit](https://github.com/CYBWithFlourish/vulnerable.so/workflows/Weekly%20Security%20Audit/badge.svg)](https://github.com/CYBWithFlourish/vulnerable.so/actions/workflows/scheduled-audit.yml)

#### 3. Documentation Validation (`.github/workflows/docs.yml`)

Runs when markdown files are modified.

**Jobs:**
- **Markdown Linting**: Validates markdown syntax and style
- **Link Checking**: Ensures all links are valid
- **Completeness Verification**: Confirms all 5 vulnerabilities are documented
- **Structure Validation**: Checks required sections exist

**Status**: [![Documentation](https://github.com/CYBWithFlourish/vulnerable.so/workflows/Documentation%20Validation/badge.svg)](https://github.com/CYBWithFlourish/vulnerable.so/actions/workflows/docs.yml)

### Running Tests Locally

Before pushing changes, run tests locally to catch issues early:

```bash
# Build all programs
anchor build

# Run Rust unit tests for specific program
cd programs/01a-missing-account-validation-vuln
cargo test-sbf

# Run all Rust tests (requires Solana test validator)
cargo test-sbf --all

# Run attack demonstrations
yarn attack:01
yarn attack:02
yarn attack:03
yarn attack:05

# Or run manually with ts-node
ts-node scripts/attacks/01-missing-account-attack.ts
```

### Understanding CI Results

The CI system provides clear, educational output:

```
✅ Build Programs: SUCCESS
   └─ Compiled 15 programs

⚠️  Attack Demo #01 (Missing Account): EXPECTED BEHAVIOR
   └─ Vulnerable: Attack succeeded ✓
   └─ Fixed: Attack blocked ✓

⚠️  Attack Demo #02 (Incorrect Authority): EXPECTED BEHAVIOR
   └─ Vulnerable: Unauthorized access ✓
   └─ Fixed: Authorization enforced ✓

⚠️  Attack Demo #03 (Unsafe Arithmetic): EXPECTED BEHAVIOR
   └─ Vulnerable: Integer underflow ✓
   └─ Fixed: Checked math prevented ✓

⚠️  Attack Demo #05 (Privilege Escalation): EXPECTED BEHAVIOR
   └─ Vulnerable: Privilege escalation ✓
   └─ Fixed: Access denied ✓

✅ All security tests passed
```

**Expected Behavior:**
- ✅ **Vulnerable versions**: Attacks succeed (demonstrating the vulnerability)
- ✅ **Fixed versions**: Attacks are blocked (demonstrating the security fix)
- ❌ **Unexpected**: If vulnerable versions block attacks OR fixed versions allow attacks

### Contributing Test Changes

When contributing, ensure:
1. All workflows pass before submitting PR
2. New vulnerabilities include corresponding tests
3. Attack scripts demonstrate both vulnerable and fixed behavior
4. Documentation is updated for new features

The CI will automatically:
- Build your changes
- Run all security tests
- Post results as PR comments
- Validate documentation updates

## Learning Path

### For Beginners

1. **Start with conceptual understanding:**
   - Read [SECURITY.md](SECURITY.md) for vulnerability overviews
   - Understand the Solana account model: [Solana Docs](https://docs.solana.com/developing/programming-model/accounts)

2. **Study one vulnerability at a time:**
   - Begin with `01-missing-account-validation`
   - Read the example README
   - Compare `example1.rs` (vulnerable) vs `example1.fix.rs` (secure)
   - Note the inline comments explaining each issue

3. **Run attack demonstrations:**
   - Execute the corresponding attack script
   - Observe how the attack works
   - See why the fix prevents it

4. **Build and test:**
   - Compile the vulnerable and fixed programs
   - Run the Anchor tests
   - Try modifying the code to break the fix

### For Intermediate Developers

1. **Deep dive into program implementations:**
   - Study the full programs in `programs/`
   - Understand the Anchor account constraints
   - Review attacker programs to see real exploit code

2. **Write your own exploits:**
   - Create custom attack transactions
   - Test edge cases
   - Document new attack vectors

3. **Contribute improvements:**
   - Add new vulnerability examples
   - Enhance documentation
   - Submit test cases

### For Security Auditors

1. **Study the vulnerability patterns:**
   - Identify common indicators in code
   - Learn Anchor-specific security constraints
   - Understand Solana runtime behaviors

2. **Practice detection:**
   - Review programs without looking at fixes
   - Identify all vulnerabilities
   - Propose remediation strategies

3. **Expand the knowledge base:**
   - Add real-world vulnerability examples
   - Document advanced attack techniques
   - Share audit findings (anonymized)

## Contribution Guidelines

We welcome contributions that enhance the educational value of this repository!

### What to Contribute

✅ **Encouraged:**
- New vulnerability examples with detailed explanations
- Improved documentation and tutorials
- Additional attack demonstrations
- Test cases and edge cases
- Translation to other languages
- Bug fixes and typo corrections

❌ **Discouraged:**
- Production-ready code (this is for education only)
- Removing vulnerability examples
- Simplifying security explanations without accuracy
- Adding dependencies without clear educational value

### How to Contribute

1. **Fork the repository**
2. **Create a feature branch:**

```bash
git checkout -b feature/new-vulnerability-example
```

3. **Follow the existing structure:**
   - Vulnerable version: `example{n}.rs`
   - Fixed version: `example{n}.fix.rs`
   - Full README with attack walkthrough
   - Inline comments explaining each step

4. **Test your code:**

```bash
anchor build
anchor test
```

5. **Submit a pull request** with:
   - Clear description of the vulnerability
   - Educational value explanation
   - Testing evidence
   - Links to relevant resources

### Code Style

- **Comments:** Explain WHY, not just WHAT
- **Naming:** Use descriptive variable and function names
- **Structure:** Follow Anchor best practices
- **Documentation:** Markdown with proper formatting, code fencing with language tags

## Resources

### Official Documentation

- **Solana Docs:** https://docs.solana.com/
- **Anchor Lang:** https://www.anchor-lang.com/docs/
- **Pinocchio:** https://github.com/anza-xyz/pinocchio

### Security Resources

- **Solana Security Best Practices:** https://docs.solana.com/developing/programming-model/security
- **Anchor Security Guidelines:** https://www.anchor-lang.com/docs/security
- **Neodyme Security Blog:** https://blog.neodyme.io/
- **Sec3 Blog:** https://www.sec3.dev/blog

### Learning Materials

- **Solana Cookbook:** https://solanacookbook.com/
- **Anchor by Example:** https://examples.anchor-lang.com/
- **Buildspace Solana Course:** https://buildspace.so/solana

### Audit Reports

- **Solana Program Library Audits:** https://github.com/solana-labs/solana-program-library/tree/master/audit
- **Real-world vulnerability disclosures:** Various security firms and bug bounty platforms

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Disclaimer

**⚠️ EDUCATIONAL USE ONLY**

This repository contains intentionally vulnerable code for educational purposes. Never deploy these programs to production or use them with real funds. The authors are not responsible for any misuse of this code.

## Acknowledgments

- Anchor team for the excellent framework and security primitives
- Solana Foundation for comprehensive documentation
- Security researchers who disclosed vulnerabilities that inspired these examples
- SuperteamNG for bounty requirements that guided this comprehensive documentation

---

**Found a vulnerability not covered here?** Open an issue or submit a PR to help others learn!
