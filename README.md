# Pry - Security Exposure Scanner

**Pry proves that an app you own is exposed, by actually trying the exploit against it.**

## What This Is

Pry verifies security exposures in web applications by actually attempting exploits, never by pattern-matching for "looks risky". Point Pry at a target you've proven you own — a live URL or a local repo booted in a sandbox — and it runs a graduated set of checks, read-only by default, and reports only what it could reproduce: the exact request, the exact response, the data it should not have returned.

## Ownership Verification (P1)

This is the first capability implemented for Pry - ownership verification. It enforces that all targets must prove ownership before any scanning occurs, implementing the security requirement:

> "Ownership is proven before anything runs, at every intensity level, including the lowest."

### Methods Supported

1. **DNS TXT Record Verification** - Add a TXT record to your domain's DNS
2. **Well-known File Verification** - Place a specific file in your app's .well-known directory  
3. **Account Linking (OAuth)** - Link your GitHub/GitLab account to verify ownership

### How It Works

```bash
# Prove ownership of a target 
pry verify-ownership https://example.com --dns-txt "expected-txt-record-value"

# Then scan the verified target
pry scan https://example.com --token "generated-token"
```

## Architecture

Pry's core architecture follows:
1. **OWN** (Ownership verification) - P1 capability
2. **INTAKE** (Target intake)
3. **PROBE** (Security checks and exploitation)
4. **PROVE** (Proof capture)
5. **REPORT** (Findings presentation)

## Key Constraints

- ✅ No scan without owner verification  
- ✅ Read-only by default, higher intensity requires confirmation
- ✅ Never claim "secure" - only "exposed" or "not reproduced"
- ✅ Execution decides, never a guess
- ✅ Minimize data touched with proof capture only
- ✅ No destructive actions without explicit sandboxed target

## Installation & Usage

```bash
# Install the package in development mode
pip install -e .

# Verify ownership using DNS TXT method
pry verify-ownership https://example.com --dns-txt "your-txt-record-value"

# Scan verified target
pry scan https://example.com --token "your-generated-token"
```

## Security Model

Pry implements a strict security gate with:
1. P1 requirement - Ownership verification (completed)  
2. No false positives in verification methods
3. Token-based access control for all scans
4. Short-lived tokens (24-hour validity)

## Contributing

All capabilities implemented in Pry follow the test-first approach - failing tests are written first and then implemented.

## License

Apache-2.0