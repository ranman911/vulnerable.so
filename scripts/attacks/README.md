# Attack Demonstration Scripts

This directory contains educational TypeScript scripts that demonstrate common security vulnerabilities in Solana programs and how to properly defend against them.

## Overview

Each script is a standalone demonstration that:
- ✅ Explains the vulnerability in detail
- ✅ Shows how the attack works on vulnerable code
- ✅ Demonstrates how the fix prevents the attack
- ✅ Includes extensive comments (40%+ of code)
- ✅ Provides real-world context and impact
- ✅ Educational summaries with best practices

## Scripts

**Note**: Script numbering follows the vulnerability catalog in the parent programs directory. Attack #04 (CPI Reentrancy) has a separate TypeScript implementation at `scripts/attacks/04-cpi-reentrancy.ts`.

### 01-missing-account-attack.ts
**Vulnerability**: Missing Account Validation  
**Attack**: Account substitution and data corruption  
**Fix**: Use `Account<'info, T>` with `has_one`, `seeds`, and `bump` constraints

Demonstrates how raw `AccountInfo` usage without proper validation allows attackers to pass malicious accounts and corrupt critical protocol data.

### 02-incorrect-authority-attack.ts
**Vulnerability**: Incorrect Authority Validation  
**Attack**: Any wallet modifying protocol fees/parameters  
**Fix**: Use `has_one = admin` constraint to link signers to stored authorities

Shows how using `Signer` alone without authority binding allows any user to execute privileged operations like changing protocol fees.

### 03-unsafe-arithmetic-attack.ts
**Vulnerability**: Unsafe Arithmetic Operations  
**Attack**: Integer underflow creating infinite balances  
**Fix**: Use `checked_sub()` and other safe arithmetic methods

Demonstrates how standard arithmetic operators (`-=`, `+=`) can underflow in release mode, allowing attackers to create infinite balances from withdrawals exceeding available funds.

### 05-signer-privilege-attack.ts
**Vulnerability**: Signer Privilege Escalation  
**Attack**: Any signer pausing/controlling protocol  
**Fix**: Use `has_one = owner` with multi-layered validation

Illustrates how accepting any `Signer` without binding it to authority fields enables privilege escalation attacks where regular users gain admin control.

## Installation

Install dependencies:

```bash
npm install
```

## Usage

Run individual demonstrations:

```bash
# Missing Account Validation attack
npm run attack:01

# Incorrect Authority attack
npm run attack:02

# Unsafe Arithmetic attack
npm run attack:03

# Signer Privilege Escalation attack
npm run attack:05
```

Or use ts-node directly:

```bash
ts-node scripts/attacks/01-missing-account-attack.ts
```

## Educational Value

These scripts are designed for:
- **Developers**: Learn to identify and fix vulnerabilities
- **Auditors**: Understand common attack patterns
- **Students**: Study Solana security best practices
- **Teams**: Training and security awareness

## Important Notes

⚠️ **For Educational Purposes Only**

These scripts demonstrate vulnerabilities in a safe, educational context. They:
- Simulate attacks without executing on real networks
- Use pseudo-code where actual exploits would occur
- Focus on explaining concepts rather than providing exploit code
- Should NOT be used for malicious purposes

## Key Takeaways

1. **Always validate accounts properly**
   - Use typed `Account<'info, T>` instead of raw `AccountInfo`
   - Apply `has_one`, `seeds`, and `bump` constraints

2. **Link signers to authorities**
   - `Signer` alone proves signature, not authorization
   - Use `has_one` to bind signers to stored authority fields

3. **Use safe arithmetic**
   - Never use `+=`, `-=`, `*=` with user-controlled values
   - Always use `checked_add()`, `checked_sub()`, etc.

4. **Defense in depth**
   - Combine multiple security layers
   - Type safety + ownership + authorization + business logic

5. **Test in release mode**
   - Some vulnerabilities only appear in production builds
   - Use `cargo build-sbf` for realistic testing

## Further Reading

- [Anchor Security Guidelines](https://www.anchor-lang.com/docs/account-constraints)
- [Solana Cookbook: Security](https://solanacookbook.com/references/security.html)
- [Neodyme Security Workshop](https://workshop.neodyme.io/)
- [Sealevel Attacks](https://github.com/coral-xyz/sealevel-attacks)

## License

MIT - Educational use only
