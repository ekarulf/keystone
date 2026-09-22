# Keystone

Hardware-backed temporary AWS credentials: the Secure Enclave on macOS, the TPM
on Windows.

## Status

Implemented. This document remains the specification: where the code and this
document disagree, that is a defect in one of them, not a licence to diverge.

Sections written as future work are marked where they are still future work. The
Implementation Plan at the end describes phases that have all shipped and is kept
as a record of the intended order.

Where the implementation deliberately falls short of a requirement here, this
document says so at that requirement rather than quietly restating the goal. Those
notes are labelled **Implementation deviation** or **Implementation note**; there
are three, on CA private-key zeroization, retry timestamps, and the clock-skew
remediation text.

## Summary

Keystone is a standalone credential helper that exchanges a hardware-backed device identity for temporary AWS credentials through AWS IAM Roles Anywhere.

The long-lived private key is generated inside the Mac’s Secure Enclave, or the PC’s TPM, and is never exported. Keystone uses that key to sign an IAM Roles Anywhere `CreateSession` request. IAM Roles Anywhere validates the signature and X.509 certificate, then returns ordinary temporary AWS credentials.

The two key stores are interchangeable from every other component’s point of view: each generates a non-exportable P-256 signing key, signs without a user-presence prompt, and has no software fallback. [Platform Support](#platform-support) describes where they differ.

```text
Secure Enclave (macOS) or TPM (Windows)
P-256 signing key
        │
        ▼
X.509 device certificate
        │
        ▼
AWS4-X509-ECDSA-SHA256
signed CreateSession request
        │
        ▼
IAM Roles Anywhere
        │
        ▼
Temporary AWS credentials
        │
        ▼
AWS CLI and AWS SDKs
```

IAM Roles Anywhere is designed to exchange X.509-authenticated signatures for temporary SigV4-compatible credentials.

Keystone avoids:

* long-lived AWS access keys;
* exportable private-key files;
* a continuously running certificate authority;
* the recurring cost of AWS Private CA;
* biometric prompts for routine credential refresh.

---

# Goals

Keystone should provide:

* hardware-backed P-256 identity generation — Secure Enclave on macOS, TPM on Windows;
* unattended P-256 signing after first device unlock;
* X.509 certificate generation and installation;
* an optional one-shot external CA;
* IAM Roles Anywhere `CreateSession` authentication;
* standard AWS `credential_process` output;
* support for multiple named profiles;
* credential caching and refresh;
* infrastructure generation through AWS CDK;
* key and trust-anchor rotation;
* clear, redacted diagnostics;
* a small and auditable private-key interface.

---

# Non-goals

The initial version does not need to provide:

* general-purpose certificate authority services;
* AWS console login;
* SSH authentication;
* general human SSO;
* Linux support;
* RSA identities;
* graphical configuration;
* automatic CDK deployment;
* automatic creation of an AWS Private CA;
* fallback to a software private key;
* broad administrative AWS permissions.

---

# Security Model

Keystone has three durable identity components:

```text
Secure Enclave private key
    Non-exportable P-256 signing key

Device certificate
    Public X.509 certificate for the Secure Enclave key

Trust-anchor certificate
    Public CA certificate registered with IAM Roles Anywhere
```

The durable private key exists only inside the Secure Enclave.

The external CA private key may be:

* retained offline for renewable certificates; or
* generated temporarily and destroyed after issuing one device certificate.

The default Keystone bootstrap model should use a temporary, one-device CA.

## Threats Keystone addresses

Keystone reduces the risk of:

* long-lived AWS access keys being copied from disk;
* a private key being copied from a PEM or PKCS#12 file;
* accidental credential inclusion in backups;
* credentials remaining valid indefinitely after device loss;
* developers sharing static AWS credentials;
* applications independently implementing credential storage.

## Threats Keystone does not address

Keystone does not prevent:

* malware running as the same user from invoking Keystone;
* malware from stealing temporary AWS session credentials;
* malware from asking the Secure Enclave to sign requests;
* misuse of an overly permissive IAM role;
* compromise of the issuing CA before its key is destroyed;
* compromise of the AWS account;
* use of credentials that were already issued before revocation;
* physical attacks against an unlocked, compromised Mac.

The Secure Enclave prevents private-key export. It is not an application-level authorization boundary between processes running as the same user.

---

# Platform Support

Keystone supports two hardware key stores:

```text
Operating system: macOS
Primary architecture: Apple Silicon
Private-key backend: Secure Enclave
Public-key algorithm: P-256
Signature algorithm: ECDSA with SHA-256
AWS signing algorithm: AWS4-X509-ECDSA-SHA256
```

```text
Operating system: Windows 10 or later
Primary architecture: x86-64
Private-key backend: TPM 2.0, via the Microsoft Platform Crypto Provider
Public-key algorithm: P-256
Signature algorithm: ECDSA with SHA-256
AWS signing algorithm: AWS4-X509-ECDSA-SHA256
```

Intel Macs with a T2 chip may be supported later after integration testing.

Everything above the key store is shared: the same identity records, the same
ephemeral CA, the same `CreateSession` client, and the same credential-process
contract. One backend is selected at compile time by target, and a target with
neither key store gets a backend whose every operation fails closed.

Three properties are the same on both platforms, and they are what make them
interchangeable:

* the private key cannot be exported. On Windows the key is created with
  `NCRYPT_EXPORT_POLICY_PROPERTY` set to zero before `NCryptFinalizeKey`, after
  which the policy is immutable;
* no operation requires user presence. Every CNG call passes
  `NCRYPT_SILENT_FLAG`, so a key that would prompt fails the call instead. Windows
  Hello is deliberately not used: it would put a gesture in front of every
  credential refresh;
* there is no software fallback. Only the TPM-backed platform provider is opened.

Two differences are worth stating because they change the code rather than the
guarantees:

* CNG signs a *digest*, where CryptoKit signs a message and hashes internally. The
  Windows backend therefore hashes once, explicitly, and implements the prehashed
  signer;
* CNG persists a key under a *name* and returns nothing storable, where CryptoKit
  returns a wrapped blob. So a Windows identity's opaque key reference is a name,
  and restoring one compares the public key CNG reports against the recorded one —
  a name is not evidence, since anything that can create a TPM key could have
  created a different key under the same name.

`key_accessibility` has no Windows equivalent: a TPM key is usable whenever the
user's profile is loaded. Keystone records the configured value and reports plainly
that Windows does not enforce it, rather than implying a guarantee the platform does
not make.

Keystone should fail clearly when:

* no hardware key store is available;
* an opaque key reference cannot be restored;
* the key requires biometric interaction;
* the certificate does not match the key;
* the certificate is expired;
* the certificate is not yet valid;
* the certificate chain is malformed;
* IAM Roles Anywhere rejects the identity.

## File permissions

The rule is the same on both platforms — refuse to read a file another local user
could have written, and never create one they could read — but it is expressed
differently, because Windows has no mode bits.

On Unix, Keystone checks the owning uid and rejects group- or world-writable files
and symlinks. On Windows it reads the file's owner SID and walks its DACL, and
rejects a file when another principal holds write-equivalent access, when the owner
is neither the caller nor the Administrators group, or when the DACL is absent — a
NULL DACL grants everyone full control, which is the most permissive state a file
can be in rather than the most restrictive.

Write-equivalent access includes `WRITE_DAC` and `WRITE_OWNER`, not only the write
bits: a principal who can rewrite the ACL can grant itself write access, so
ignoring those would make the check decorative.

Private files are created with an owner-only DACL supplied to `CreateFileW` rather
than applied afterwards, for the same reason Unix passes a mode to `open`: between
creating a file and fixing its ACL, its contents are readable by whoever the
containing directory allows. Inheritance is blocked with
`PROTECTED_DACL_SECURITY_INFORMATION`, so a loosened parent directory cannot widen
access to a file Keystone reports as private.

Windows data lives under `%LOCALAPPDATA%\Keystone`, not `%APPDATA%`. The roaming
profile syncs to a file server, and an identity bound to one machine's TPM must not
be copied to machines where the key it names does not exist.

## Unsafe code

The workspace sets `unsafe_code = "forbid"`. CNG and the Win32 security APIs are raw
FFI with no safe wrapper, so every `unsafe` block Keystone executes lives in one
crate, `keystone-win32-sys`, which sets the lint to `deny` and marks each block with
an explicit allow and a safety comment. Auditing Keystone's use of unsafe means
reading one directory. The bindings themselves come from Microsoft's `windows-sys`
rather than hand-written `extern` blocks, because a mistyped FFI signature is
undefined behavior that a macOS build cannot catch.

---

# Repository Layout

Recommended Rust workspace:

```text
keystone/
├── Cargo.toml
├── crates/
│   ├── keystone-core/
│   ├── keystone-macos/
│   ├── keystone-windows/
│   ├── keystone-win32-sys/
│   ├── keystone-pki/
│   ├── keystone-roles-anywhere/
│   ├── keystone-infra/
│   ├── keystone-cli/
│   └── keystone-tests/
├── templates/
│   └── cdk-typescript-v1/
├── tests/
│   ├── fixtures/
│   ├── golden/
│   └── integration/
└── docs/
```

`keystone-tests` is not in the list above but exists in the implementation: the
suites under `tests/` are integration tests, which Cargo will only run from a
package, so `keystone-tests` is the package whose `[[test]]` targets point at
them. It ships no library code.

## `keystone-core`

Portable application types:

* configuration;
* profile names;
* identity metadata;
* session credentials;
* cache behavior;
* time abstractions;
* error types;
* redaction.

## `keystone-macos`

macOS-specific behavior:

* Secure Enclave availability;
* P-256 key generation;
* key restoration;
* ECDSA signing;
* Keychain interaction;
* access-control configuration.

## `keystone-windows`

The same behavior against the TPM:

* TPM availability;
* P-256 key generation, non-exportable and signing-only;
* key restoration, including the public-key comparison that makes a stored key
  name safe to trust;
* ECDSA signing over a caller-supplied digest;
* key policy, and reporting what Windows does and does not enforce.

## `keystone-win32-sys`

The FFI quarantine, and the only crate in the workspace permitted to use `unsafe`:

* CNG key creation, opening, export, signing, and deletion;
* file owner and DACL inspection;
* owner-only file creation and DACL application.

It contains no policy. Failures are returned as the raw status the API reported, and
`keystone-windows` decides what each one means.

## `keystone-pki`

Certificate functionality:

* X.509 certificate construction;
* PKCS#10 CSR construction;
* temporary CA generation;
* certificate issuance;
* certificate validation;
* public-key matching;
* PEM and DER parsing.

## `keystone-roles-anywhere`

AWS protocol behavior:

* `CreateSession` request serialization;
* AWS4-X509 canonicalization;
* certificate-header encoding;
* ECDSA authorization headers;
* regional endpoint selection;
* HTTP transport;
* response validation.

## `keystone-infra`

Infrastructure generation:

* TypeScript CDK templates;
* trust-anchor generation;
* Roles Anywhere profile generation;
* IAM role generation;
* CloudFormation output parsing;
* local Keystone profile synchronization.

## `keystone-cli`

Command-line interface and AWS `credential_process` integration.

---

# Dependencies

The workspace `Cargo.toml` is authoritative. This was written as a guess before
implementation; it is kept for the reasoning, with the outcome recorded.

Dropped as unnecessary: `anyhow` (the library defines its own error enum, and a
CLI that must not leak secrets into messages wants the enum), `http` and `url`
(the one endpoint is built by `format!`), `rustls` (reached only through
`reqwest`'s `rustls-tls` feature), `rand_core` (`rand` suffices).

Replaced: `x509-cert` by **`x509-parser`** with its `verify` feature, because
signature verification had to be real — comparing issuer and subject names would
accept a forged chain.

Never needed: **`security-framework`** and **`core-foundation`**. The original plan
assumed Keychain integration, but `SecureEnclave.P256.Signing.PrivateKey` is not a
Keychain API — it returns a wrapped-key blob that Keystone stores itself, so no
Keychain access is involved. See "Secure Enclave Identity".

Added: `p256` (verification and test signing), `rcgen` (certificate and CSR
generation), `tera` (CDK templates), `rustix` (a safe `geteuid` for the
file-ownership check, since the workspace forbids `unsafe_code`).

Kept as planned: `base64`, `clap`, `fs2`, `hex`, `reqwest` with `rustls-tls`,
`serde`, `serde_json`, `sha2`, `thiserror`, `time`, `toml`, `zeroize`, and
`cryptokit-rs` for Secure Enclave key operations.

---

# Terminology

## Keystone identity

A Secure Enclave private key and its corresponding public metadata.

## Keystone profile

A local named configuration connecting one Keystone identity to one IAM Roles Anywhere profile and IAM role.

## Roles Anywhere profile

An AWS resource listing the IAM roles that may be requested through a `CreateSession` operation.

## Trust anchor

An AWS IAM Roles Anywhere resource containing either:

* an AWS Private CA reference; or
* a public external CA certificate.

AWS supports trust anchors based on uploaded external CA certificates.

## Ephemeral CA

A CA private key that exists only during Keystone bootstrap, issues one device certificate, and is then destroyed.

The CA certificate remains public and is registered as the IAM Roles Anywhere trust anchor.

---

# CLI Overview

```text
keystone init
keystone bootstrap
keystone enroll csr
keystone enroll install
keystone inspect
keystone credential-process
keystone test
keystone doctor
keystone rotate
keystone revoke
keystone profiles
keystone infra cdk init
keystone infra cdk print
keystone infra cdk render
keystone infra cdk sync-profile
```

## Global options

Accepted by every subcommand:

```text
--home <DIR>                  Override Keystone's data directory. Also read from
                              the KEYSTONE_HOME environment variable, which the
                              flag overrides. Intended for tests and for keeping
                              more than one independent Keystone tree on a
                              machine.
--allow-unsafe-permissions    Read configuration, identity, certificate, and
                              credential-cache files even when another local user
                              can write them. Refused by default; see
                              File permissions. Relaxes only the permission
                              check, never any content validation.
-v, --verbose                 Print more diagnostic detail on standard error.
                              Never changes what goes to standard output, so it
                              is safe under credential-process.
```

## Per-command options worth naming here

Beyond the flags the command sections below describe:

```text
credential-process --no-cache    Ignore the cache and perform a fresh exchange.
credential-process --redact      On by default; --redact false is the deliberate
test --redact                    step that unredacts --debug-signing output.
rotate --activate                Switch the profile to the new identity now.
                                 Without it, rotate prepares the identity and
                                 stops before the switch, so the new trust anchor
                                 can be deployed and tested first. This is what
                                 makes the safe sequence in Rotation safe.
infra cdk render --file <PATH>   Which generated file to print, e.g.
                                 lib/keystone-personal-stack.ts. Required:
                                 `render` prints one file, where `print` shows
                                 the plan.
```

---

# Configuration

Default configuration file:

```text
~/Library/Application Support/Keystone/config.toml
```

Example:

```toml
version = 1

[profiles.personal]
region = "us-east-1"

trust_anchor_arn = "arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/..."
roles_anywhere_profile_arn = "arn:aws:rolesanywhere:us-east-1:123456789012:profile/..."
role_arn = "arn:aws:iam::123456789012:role/KeystonePersonalMac"

role_session_name = "example-laptop"
duration_seconds = 3600

key_id = "019c..."
certificate_fingerprint_sha256 = "7f2c..."
ca_fingerprint_sha256 = "4c91..."

refresh_before_seconds = 300
connect_timeout_seconds = 5
request_timeout_seconds = 20

key_accessibility = "after-first-unlock"

[profiles.personal.issuer]
mode = "ephemeral-ca"
renewable = false
trust_anchor_rotation_required = true
certificate_expires_at = "2031-07-25T00:00:00Z"
```

Configuration contains no:

* AWS access key;
* AWS secret access key;
* AWS session token;
* private-key scalar;
* CA private key.

Recommended permissions:

```text
directory: 0700
config:    0600
```

Keystone should reject configuration files writable by another user unless the caller explicitly provides an unsafe override.

---

# Local Data Layout

```text
~/Library/Application Support/Keystone/
├── config.toml
├── identities/
│   └── <key-id>.json
├── certificates/
│   └── <certificate-fingerprint>/
│       ├── leaf.der
│       └── ca.der
└── generated/
    └── <profile>/
```

Cache location:

```text
~/Library/Caches/Keystone/
├── credentials/
└── locks/
```

## Identity metadata

```json
{
  "version": 1,
  "key_id": "019c...",
  "key_type": "secure-enclave-p256-signing",
  "public_key_sec1": "base64...",
  "public_key_fingerprint_sha256": "7f2c...",
  "opaque_key_reference": "base64...",
  "created_at": "2026-07-25T22:00:00Z"
}
```

The opaque key reference is not an exported private scalar, but it should still be protected against replacement and deletion.

---

# Secure Enclave Identity

## Key requirements

```text
Curve: P-256
Operation: ECDSA signing
Storage: Secure Enclave
Exportable: no
Device-bound: yes
Biometric prompt: no
```

The key used for AWS authentication should be dedicated to Keystone.

Do not reuse a key used for:

* ECDH;
* document signatures;
* SSH;
* application payload signatures;
* unrelated authentication protocols.

## Access policy

Recommended default:

```text
private-key usage
after first unlock
this device only
no user-presence requirement
```

Supported configuration:

```toml
key_accessibility = "after-first-unlock"
```

or:

```toml
key_accessibility = "when-unlocked"
```

### `after-first-unlock`

Allows credential refresh after the user has logged in once following boot, including while the screen is later locked.

Best for unattended agents.

### `when-unlocked`

Allows signing only while the device is unlocked.

Best for interactive developer workflows.

Keystone must not silently add biometric or user-presence requirements.

---

# Signing Interface

Avoid an ambiguous `sign` API.

```rust
pub trait KeystoneSigningIdentity {
    fn key_id(&self) -> &KeyId;

    fn public_key_sec1(
        &self,
    ) -> Result<[u8; 65], KeystoneError>;

    fn sign_message_ecdsa_sha256(
        &self,
        message: &[u8],
    ) -> Result<DerEcdsaSignature, KeystoneError>;
}
```

Resolved during implementation: CryptoKit's `signature(for:)` takes the **original
message and hashes it internally**. The string-to-sign is therefore passed
unhashed, which also matches what the official AWS helper does.

Do not accidentally hash the Roles Anywhere string-to-sign twice.

Both modes exist as distinct methods so the distinction cannot be made by
accident — `sign_prehashed_sha256` lives on a separate `PrehashedSigner` trait, so
reaching for it is deliberate:

```rust
fn sign_message_ecdsa_sha256(...)  // Signer
fn sign_prehashed_sha256(...)      // PrehashedSigner
```

---

# `keystone init`

Create a local Secure Enclave identity without issuing a certificate.

```bash
keystone init --profile personal --region us-east-1
```

Steps:

1. Verify that the Secure Enclave is available.
2. Generate a P-256 signing key.
3. Configure unattended access control.
4. Persist the opaque Secure Enclave key reference.
5. Export the 65-byte SEC1 public key.
6. Compute a SHA-256 public-key fingerprint.
7. Generate a random Keystone key ID.
8. Create a local profile stub.
9. Print the next enrollment step.

Example output:

```text
Created Keystone identity: personal
Key backend: Secure Enclave
Algorithm: P-256 ECDSA
Key ID: 019c...
Fingerprint: SHA256:7f2c...
Certificate status: not enrolled
```

---

# Device Certificate

The Keystone device certificate should contain:

```text
Version: X.509 v3
Public key: P-256
Basic constraints: critical, CA=false
Key usage: critical, digitalSignature
Signature: ecdsa-with-SHA256
```

IAM Roles Anywhere requires an X.509 v3 end-entity certificate that permits digital signatures and is not a CA certificate.

Suggested subject:

```text
CN=<device-name>
OU=Keystone Devices
O=<organization>
```

Required subject alternative name:

```text
URI:urn:keystone:device:<key-id>
```

Example:

```text
URI:urn:keystone:device:019c1f0e-32a1-7cab-a4f2-...
```

The URI SAN is the preferred stable identity value used in IAM trust-policy conditions.

Display-oriented fields such as `CN` should not be the primary authorization mechanism.

---

# CSR Enrollment

Keystone can generate a PKCS#10 CSR for an existing CA.

```bash
keystone enroll csr \
    --profile personal \
    --subject "CN=example-laptop,OU=Keystone Devices,O=Example" \
    --san-uri "urn:keystone:device:019c..." \
    --output example-laptop.csr
```

Flow:

```text
Secure Enclave key
      │
      ├── export public key
      ├── construct CertificationRequestInfo
      └── sign CertificationRequestInfo
                │
                ▼
             PKCS#10 CSR
```

The CSR signature algorithm is:

```text
ecdsa-with-SHA256
```

Keystone should verify the CSR signature before writing the file.

---

# Certificate Installation

```bash
keystone enroll install \
    --profile personal \
    --certificate leaf.pem \
    --chain issuer.pem
```

Validation:

1. Parse the certificate.
2. Confirm X.509 version 3.
3. Confirm P-256 public key.
4. Confirm `digitalSignature` key usage.
5. Confirm `CA=false`.
6. Confirm certificate validity.
7. Confirm the public key exactly matches the Secure Enclave key.
8. Confirm the expected Keystone URI SAN exists.
9. Validate the supplied issuer chain.
10. Store public certificate material.
11. Record certificate fingerprints and expiration.

A V0 implementation may store public DER certificate files locally rather than constructing a native Keychain identity.

---

# Ephemeral CA Bootstrap

## Purpose

For a small Keystone installation, running a permanent private CA or paying for AWS Private CA is unnecessary.

Keystone can generate a one-shot CA, issue one device certificate, and destroy the CA private key.

```text
Temporary software CA private key
            │
            ├── creates self-signed CA certificate
            ├── signs Keystone device certificate
            └── is destroyed

Persistent:
    public CA certificate
    public device certificate
    Secure Enclave device key
```

## Command

```bash
keystone bootstrap \
    --profile personal \
    --ca-mode ephemeral \
    --device-name example-laptop \
    --leaf-validity 5y \
    --ca-validity 10y \
    --generate-cdk ./keystone-infra
```

## Bootstrap sequence

1. Generate the Secure Enclave P-256 signing key.
2. Generate a temporary software P-256 CA key.
3. Create a self-signed CA certificate.
4. Construct the Keystone device certificate.
5. Sign the device certificate with the CA.
6. Verify the leaf certificate and chain.
7. Verify the leaf public key matches the Secure Enclave key.
8. Persist only public certificate material.
9. Generate the CDK project.
10. Zeroize the CA private scalar.
11. Exit the short-lived bootstrap process.

## CA certificate

```text
Subject:
  CN=Keystone Ephemeral CA <key-id>

Basic Constraints:
  critical
  CA=true
  pathLen=0

Key Usage:
  critical
  keyCertSign
  cRLSign

Public key:
  P-256

Signature:
  ecdsa-with-SHA256

Validity:
  configurable, default 10 years
```

## Device certificate

```text
Subject:
  CN=<device-name>
  OU=Keystone Devices

Subject Alternative Name:
  URI=urn:keystone:device:<key-id>

Basic Constraints:
  critical
  CA=false

Key Usage:
  critical
  digitalSignature

Public key:
  Secure Enclave P-256 public key

Signature:
  ecdsa-with-SHA256

Validity:
  configurable, default 5 years
```

## CA private-key handling

The CA key must not be written to the ordinary filesystem.

Preferred implementation:

```text
parent Keystone process
        │
        ▼
short-lived bootstrap worker
        │
        ├── generates CA key
        ├── signs certificates
        ├── returns public artifacts
        ├── zeroizes private scalar
        └── exits
```

Perfect deletion from process memory cannot be proven on a general-purpose OS, but a short-lived process and explicit zeroization significantly reduce persistence.

**Implementation deviation.** Steps 10 and the "zeroizes private scalar" box above are *not* implemented as written. `keystone-pki` generates the CA key as an `rcgen::KeyPair`, which holds the private scalar inside *ring* and exposes no way to overwrite it; rcgen's internal PKCS#8 buffer is not reachable either. What the implementation does provide is unreachability — no accessor, no serialization path, and the key dropped before `issue` returns — plus the short-lived process this section calls for. The residual exposure is a core dump, an attached debugger, or swapped-out pages during the seconds a bootstrap runs. Closing it properly requires a zeroize-aware P-256 key type rather than a `Drop` impl that cannot reach the bytes. See `EphemeralCaKey` in `crates/keystone-pki/src/ephemeral_ca.rs`, which documents the same split.

## Output

```text
keystone-bootstrap/
├── ca-certificate.pem
├── device-certificate.pem
├── device-chain.pem
├── bootstrap-manifest.json
├── keystone-profile.toml
└── cdk/
```

The final output must not contain:

```text
ca-private-key.pem
```

---

# Ephemeral CA Tradeoffs

## Benefits

* no AWS Private CA monthly fee;
* no online CA;
* no long-lived CA private key;
* one-device trust boundary;
* simple revocation by disabling the trust anchor;
* small operational footprint.

## Limitations

* the device certificate cannot be renewed;
* a new chain and trust anchor are required for rotation;
* a CRL cannot be updated after the CA key is destroyed;
* each device consumes one trust anchor;
* the CA must remain valid longer than the leaf certificate.

IAM Roles Anywhere trust anchors are regional resources. The default trust-anchor quota should be checked before using one CA per device; AWS currently documents IAM Roles Anywhere quotas per account and Region.

---

# Reusable KMS-backed CA

`keystone ca init` and `keystone ca issue` support a deliberately small external
CA whose signing key is an existing AWS KMS `ECC_NIST_P256` `SIGN_VERIFY` key.
Keystone retrieves the SubjectPublicKeyInfo with `GetPublicKey` and asks KMS to
sign rcgen's raw certificate body with `ECDSA_SHA_256` and `MessageType=RAW`.
Every returned DER ECDSA signature is verified locally over that same raw body,
which both detects malformed KMS responses and prevents accidental double
hashing.

The PKI crate owns subject, CSR, extension, validity, serial-number, and chain
policy behind rcgen's generic signing interface. The CLI crate alone depends on
the AWS SDK and adapts KMS to that interface. The normal AWS credential provider
chain is used, optionally selecting `--aws-profile`; no credentials or CA
configuration are persisted.

Initialization requires `--kms-key`, `--region`, `--subject`, and `--output` and
defaults to ten years. Issuance additionally requires `--ca-certificate` and
`--csr` and defaults to one year. The CA is self-signed, has `CA=true`,
`pathLen=0`, and only `keyCertSign` plus `cRLSign`. Issued certificates preserve
the validated CSR subject, P-256 public key, and sole Keystone device URI SAN,
but no arbitrary requested extensions. The CA chooses validity and a random
128-bit positive serial, and a leaf may not outlive its CA.

KMS key provisioning, aliases, key policies, rotation, deletion, revocation,
CRL/OCSP service, automatic approval, subordinate CAs, and network enrollment
are outside V1. Device roles have no KMS permissions. Administrators require
`kms:GetPublicKey` and `kms:Sign`; the latter should be constrained with
`kms:SigningAlgorithm = ECDSA_SHA_256`. A reusable authority reduces trust-anchor
churn but increases blast radius: control of the KMS key or administrator
signing credentials can issue certificates for every relying trust anchor,
although the CA private scalar remains non-exportable.

For larger fleets, use:

```text
offline organizational CA
    └── many Keystone device certificates
```

rather than one trust anchor per device.

---

# Revocation Model

For a one-device ephemeral CA, revocation means disabling or deleting the associated trust anchor.

```text
device lost or compromised
        │
        ▼
disable IAM Roles Anywhere trust anchor
        │
        ▼
new CreateSession requests fail
```

Already-issued AWS credentials remain valid until their expiration.

Recommended session duration:

```text
3600 seconds
```

For emergency response, also consider:

* disabling the Roles Anywhere profile;
* removing the IAM role from the profile;
* modifying the role trust policy;
* revoking active application access where possible.

---

# Rotation

An identity issued by a destroyed CA cannot be renewed.

Rotation creates a new identity chain:

```text
new Secure Enclave key
        +
new ephemeral CA
        +
new device certificate
        +
new IAM trust anchor
```

Command:

```bash
keystone rotate \
    --profile personal \
    --ca-mode ephemeral \
    --generate-cdk ./keystone-rotation
```

Safe sequence:

1. Generate a new hardware key.
2. Generate a new ephemeral CA.
3. Issue a new device certificate.
4. Deploy a second trust anchor.
5. Add or deploy the new Roles Anywhere profile.
6. Test `CreateSession`.
7. Atomically switch the local Keystone profile.
8. Disable the old trust anchor.
9. Retain it briefly for rollback.
10. Delete the old trust anchor and local key reference.

Keystone should warn before expiry:

```text
Certificate expires in 90 days.

This certificate was issued by a destroyed ephemeral CA and cannot
be renewed. Run:

    keystone rotate --profile personal
```

---

# IAM Roles Anywhere Resources

A Keystone deployment requires:

1. a trust anchor;
2. an IAM role;
3. an IAM Roles Anywhere profile.

IAM Roles Anywhere checks that the attached certificate chains to a configured trust anchor and that the request signature validates against the leaf certificate.

## Trust anchor

For the ephemeral CA model, the trust anchor source is:

```text
CERTIFICATE_BUNDLE
```

containing the public CA certificate.

## IAM role

The role trusts:

```text
rolesanywhere.amazonaws.com
```

The role trust policy should restrict access by:

* trust-anchor ARN;
* AWS account;
* mapped device URI SAN.

## Roles Anywhere profile

The profile specifies:

* allowed IAM role ARNs;
* credential duration;
* whether custom role-session names are accepted;
* certificate attribute mappings;
* optional session policies.

The AWS CDK currently exposes Roles Anywhere through generated L1 constructs, including `CfnTrustAnchor` and `CfnProfile`.

---

# AWS4-X509 Signing

IAM Roles Anywhere uses a SigV4-like signing process.

For a P-256 certificate:

```text
AWS4-X509-ECDSA-SHA256
```

AWS places the certificate serial number in the credential field where a normal SigV4 request would contain the access-key ID.

## CreateSession endpoint

Conceptually:

```text
POST https://rolesanywhere.<region>.amazonaws.com/sessions
```

The exact endpoint should be selected using an AWS endpoint ruleset or a tested partition table.

## Request body

Conceptually:

```json
{
  "profileArn": "arn:aws:rolesanywhere:us-east-1:123456789012:profile/...",
  "roleArn": "arn:aws:iam::123456789012:role/KeystonePersonalMac",
  "trustAnchorArn": "arn:aws:rolesanywhere:us-east-1:123456789012:trust-anchor/...",
  "durationSeconds": 3600,
  "roleSessionName": "example-laptop"
}
```

Serialize the body once.

The exact serialized bytes must be:

* hashed for the canonical request; and
* sent as the HTTP request body.

## Required headers

The final header set should follow the current Roles Anywhere specification and official helper implementation.

It will include values such as:

```text
content-type
host
x-amz-date
x-amz-x509
x-amz-x509-chain
authorization
```

Certificate encoding, chain order, and header canonicalization should be ported from the official AWS helper rather than inferred.

## Canonical request

```text
CanonicalRequest =
    HTTPMethod + "\n" +
    CanonicalURI + "\n" +
    CanonicalQueryString + "\n" +
    CanonicalHeaders + "\n" +
    SignedHeaders + "\n" +
    HexLower(SHA256(RequestBody))
```

For `CreateSession`:

```text
HTTPMethod = POST
CanonicalURI = /sessions
```

## Credential scope

```text
YYYYMMDD/<region>/rolesanywhere/aws4_request
```

## String to sign

```text
StringToSign =
    "AWS4-X509-ECDSA-SHA256" + "\n" +
    AmzDate + "\n" +
    CredentialScope + "\n" +
    HexLower(SHA256(CanonicalRequest))
```

## Secure Enclave operation

```text
signature_der =
    ECDSA-P256-SHA256(
        Secure Enclave private key,
        StringToSign
    )
```

## Authorization header

Conceptually:

```text
Authorization:
AWS4-X509-ECDSA-SHA256
Credential=<decimal-certificate-serial>/<scope>,
SignedHeaders=<signed-header-list>,
Signature=<hex-encoded-signature>
```

The implementation must verify whether the DER-encoded ECDSA signature is hex-encoded directly. This behavior should be copied from the official helper and covered by golden tests.

---

# Do Not Reimplement AWS Canonicalization Blindly

The recommended implementation strategy is:

1. Inspect the official `aws_signing_helper` source.
2. Port its Roles Anywhere canonicalization.
3. Port its certificate-header construction.
4. Port its authorization-header construction.
5. Replace only the private-key backend.
6. Compare Keystone output against the official helper.
7. maintain golden request fixtures.

Keystone’s novel security boundary should be the Secure Enclave signer, not a novel AWS signing implementation.

---

# Internal Roles Anywhere Interfaces

```rust
pub trait AwsX509Identity {
    fn certificate_serial_decimal(
        &self,
    ) -> Result<String, KeystoneError>;

    fn leaf_certificate_der(&self) -> &[u8];

    fn certificate_chain_der(&self) -> &[Vec<u8>];

    fn sign_string_to_sign(
        &self,
        string_to_sign: &[u8],
    ) -> Result<Vec<u8>, KeystoneError>;
}
```

```rust
pub struct RolesAnywhereRequestSigner<I> {
    identity: I,
    region: String,
    clock: Arc<dyn Clock>,
}
```

```rust
pub struct CreateSessionRequest {
    pub profile_arn: String,
    pub role_arn: String,
    pub trust_anchor_arn: String,
    pub duration_seconds: u32,
    pub role_session_name: Option<String>,
}
```

---

# `keystone credential-process`

Command:

```bash
keystone credential-process --profile personal
```

Output must follow the AWS process credential-provider contract:

```json
{
  "Version": 1,
  "AccessKeyId": "ASIA...",
  "SecretAccessKey": "...",
  "SessionToken": "...",
  "Expiration": "2026-07-26T01:15:00Z"
}
```

Rules:

* credential JSON is the only content written to standard output;
* diagnostics go to standard error;
* successful output ends with a newline;
* credential values are never logged;
* failures exit nonzero;
* no partial JSON is written on failure.

## AWS configuration

```ini
[profile keystone-personal]
credential_process = /usr/local/bin/keystone credential-process --profile personal
region = us-east-1
```

Usage:

```bash
AWS_PROFILE=keystone-personal aws sts get-caller-identity
```

Applications using normal AWS SDK credential resolution can use the same profile.

---

# Credential Response Types

```rust
pub struct AwsSessionCredentials {
    pub access_key_id: String,
    pub secret_access_key: Zeroizing<String>,
    pub session_token: Zeroizing<String>,
    pub expiration: OffsetDateTime,
}
```

```rust
#[derive(Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct CredentialProcessOutput {
    pub version: u8,
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: String,
    pub expiration: String,
}
```

The output `Version` is:

```text
1
```

Keystone should verify:

* access-key ID is nonempty;
* secret access key is nonempty;
* session token is nonempty;
* expiration is in the future;
* the returned role is compatible with the requested role, when that metadata is available.

---

# Credential Caching

## V0

The simplest secure behavior is no persistent cache.

Each invocation of:

```text
keystone credential-process
```

performs a new Roles Anywhere exchange.

The AWS SDK caches returned credentials in the calling process until refresh is required.

## V1

As implemented: a JSON cache under the cache directory, written mode 0600, one
file per profile. Keychain backing is **still future work** — the note below about
avoiding plaintext JSON describes the intended end state, not what ships.

Avoid storing session credentials in plaintext JSON unless explicitly configured.

Cache lookup:

```text
if now < expiration - refresh_before:
    return cached credentials
else:
    refresh
```

Default:

```text
refresh_before = 5 minutes
```

## Concurrent refresh

Use a per-profile lock:

```text
~/Library/Caches/Keystone/locks/<profile>.lock
```

Flow:

1. Read cache.
2. Return if sufficiently fresh.
3. Acquire profile lock.
4. Read cache again.
5. Return if another process refreshed it.
6. Call Roles Anywhere.
7. Atomically update cache.
8. Release lock.

A refresh failure should not discard cached credentials that are still valid.

---

# Clock Handling

AWS request signing is time-sensitive.

Keystone should:

* use UTC;
* capture one timestamp per signing attempt;
* use that timestamp consistently;
* detect obviously invalid local clock values;
* distinguish clock-skew failures from certificate failures;
* avoid infinite retries.

Example:

```text
IAM Roles Anywhere rejected the signature timestamp.

Confirm that automatic time synchronization is enabled: on macOS, System
Settings > General > Date & Time; on Windows, Settings > Time & language >
Date & time.
```

The implementation does not emit this text. `keystone-core`'s local clock check
returns `KeystoneError::ClockSkew` ("system clock may be incorrect"), and a
skew rejection *from AWS* surfaces as `RolesAnywhereRejected` with the service's
own code. `keystone doctor`'s "local clock" check is where a user is pointed at
the clock; the per-platform remediation above is not yet written anywhere.

---

# HTTP Behavior

Requirements:

* TLS 1.2 or newer;
* normal certificate validation;
* no insecure TLS option;
* bounded connect timeout;
* bounded request timeout;
* redirects disabled;
* request body serialized once;
* transient retries only;
* credentials and authorization headers redacted.

Recommended retryable failures:

```text
HTTP 429
HTTP 500
HTTP 502
HTTP 503
HTTP 504
connection reset
temporary DNS failure
```

Maximum attempts:

```text
3
```

Use exponential backoff with jitter.

Do not automatically retry:

```text
HTTP 400
HTTP 401
HTTP 403
invalid certificate
expired certificate
invalid signature
invalid role
invalid profile
```

Each retry should build and sign a fresh request with a current timestamp.

**Implementation note.** Each retry does build and sign a fresh request, but the timestamp comes from the client's injected clock, and the CLI injects a fixed one — the single timestamp the command validated, per "capture one timestamp per signing attempt; use that timestamp consistently" above. The two requirements only coexist because the full retry sequence completes in under a second, so a fixed timestamp cannot drift into AWS's skew window. A retry policy with minutes of backoff would have to take a system clock instead.

---

# `keystone inspect`

```bash
keystone inspect --profile personal
```

Example output:

```text
Profile: personal
Key backend: Secure Enclave
Key algorithm: P-256 ECDSA
Key ID: 019c...
Public-key fingerprint: SHA256:7f2c...

Certificate subject: CN=example-laptop
Certificate issuer: CN=Keystone Ephemeral CA 019c...
Certificate serial: 4837201
Certificate expires: 2031-07-25T00:00:00Z
Certificate SAN: urn:keystone:device:019c...

Issuer mode: ephemeral-ca
Renewable: no
Trust-anchor rotation required: yes

AWS region: us-east-1
Trust-anchor ARN: arn:aws:rolesanywhere:...
Roles Anywhere profile ARN: arn:aws:rolesanywhere:...
Role ARN: arn:aws:iam::...
```

No secret data should be printed.

---

# `keystone test`

```bash
keystone test --profile personal
```

The command:

1. validates the local identity;
2. creates a Roles Anywhere session;
3. validates the returned credentials;
4. optionally calls `sts:GetCallerIdentity`;
5. prints the resulting ARN and expiration;
6. never prints credential secrets.

Example:

```text
IAM Roles Anywhere authentication succeeded.

Caller ARN:
arn:aws:sts::123456789012:assumed-role/KeystonePersonalMac/example-laptop

Credentials expire:
2026-07-26T01:15:00Z
```

---

# `keystone doctor`

Checks:

* key-store availability (Secure Enclave or TPM);
* key restoration;
* unattended signing;
* configuration permissions;
* certificate parsing;
* certificate validity;
* certificate/key match;
* CA chain validation;
* URI SAN presence;
* endpoint reachability;
* local clock;
* Roles Anywhere authentication;
* AWS shared-config integration;
* certificate expiration;
* trust-anchor configuration.

---

# CDK Generation

Keystone should generate the infrastructure required to connect a local Keystone profile to IAM Roles Anywhere.

## Commands

```text
keystone infra cdk init
keystone infra cdk print
keystone infra cdk render
keystone infra cdk sync-profile
```

## `keystone infra cdk init`

Generate a complete TypeScript CDK application:

```bash
keystone infra cdk init \
    --profile personal \
    --output ./keystone-infra \
    --stack-name KeystonePersonal \
    --role-name KeystonePersonalMac
```

For an ephemeral CA profile, Keystone already knows:

* the public CA certificate;
* device URI SAN;
* Keystone key ID;
* certificate fingerprints;
* target AWS region.

No CA ARN is required.

## Generated project

For `--stack-name KeystonePersonal`. The `bin/`, `lib/`, and `test/` filenames are
derived from the stack name, so they change with it.

```text
keystone-infra/
├── bin/
│   └── keystone-personal.ts
├── lib/
│   └── keystone-personal-stack.ts
├── test/
│   └── keystone-personal-stack.test.ts
├── certificates/
│   └── keystone-ca.pem
├── policy/
│   └── inline-policy.json        (only with --policy)
├── cdk.json
├── package.json
├── tsconfig.json
├── README.md
├── .gitignore
└── keystone.profile.toml
```

The project contains only public certificate data.

---

# Generated CDK Resources

The generated stack creates:

* `AWS::RolesAnywhere::TrustAnchor`;
* `AWS::RolesAnywhere::Profile`;
* `AWS::IAM::Role`;
* CloudFormation outputs.

## Trust anchor

```typescript
const trustAnchor =
  new rolesanywhere.CfnTrustAnchor(
    this,
    "KeystoneTrustAnchor",
    {
      name: props.trustAnchorName,
      enabled: true,
      source: {
        sourceType: "CERTIFICATE_BUNDLE",
        sourceData: {
          x509CertificateData:
            caCertificatePem,
        },
      },
    },
  );
```

The CA certificate is public and may be embedded in the synthesized CloudFormation template.

## IAM principal

```typescript
const principal =
  new iam.ServicePrincipal(
    "rolesanywhere.amazonaws.com",
    {
      conditions: {
        ArnEquals: {
          "aws:SourceArn":
            trustAnchor.attrTrustAnchorArn,
        },
        StringEquals: {
          "aws:SourceAccount":
            Stack.of(this).account,
        },
      },
    },
  );
```

Certificate-specific authorization should also be applied through IAM Roles Anywhere certificate attribute mappings and principal tags.

The exact tag key must be validated against the current AWS attribute-mapping behavior.

## IAM role

```typescript
const role = new iam.Role(
  this,
  "KeystoneRole",
  {
    roleName: props.roleName,
    assumedBy: principal,
    maxSessionDuration: Duration.seconds(
      props.sessionDurationSeconds,
    ),
  },
);
```

The generated role must not default to administrator permissions.

## Roles Anywhere profile

```typescript
const rolesAnywhereProfile =
  new rolesanywhere.CfnProfile(
    this,
    "KeystoneRolesAnywhereProfile",
    {
      name: props.profileName,
      enabled: true,
      durationSeconds:
        props.sessionDurationSeconds,
      roleArns: [role.roleArn],
      acceptRoleSessionName: true,
      requireInstanceProperties: false,
      attributeMappings: [
        {
          certificateField: "x509SAN",
          mappingRules: [
            {
              specifier: "URI",
            },
          ],
        },
      ],
    },
  );
```

## Device authorization

The generated IAM trust policy should require the device URI SAN after it has been mapped to a session principal tag:

```text
urn:keystone:device:<key-id>
```

Conceptually:

```typescript
{
  StringEquals: {
    "aws:PrincipalTag/x509SAN/URI":
      props.deviceSanUri,
  },
}
```

The generated code should contain a warning that the exact condition key must match the selected Roles Anywhere attribute mapping.

---

# CDK Permission Modes

## Empty role

The default, when neither `--policy` nor `--managed-policy-arn` is given:

```bash
keystone infra cdk init \
    --profile personal
```

The generated role contains no workload permissions.

## Inline policy

```bash
keystone infra cdk init \
    --profile personal \
    --policy ./policy.json
```

## Managed policy

```bash
keystone infra cdk init \
    --profile personal \
    --managed-policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess
```

Keystone must never attach:

```text
AdministratorAccess
```

by default.

---

# Existing Role Mode

```bash
keystone infra cdk init \
    --profile personal \
    --existing-role-arn arn:aws:iam::123456789012:role/Developer
```

The generated stack creates:

* the trust anchor;
* the Roles Anywhere profile;
* CloudFormation outputs.

It does not automatically modify an externally managed role.

The generated README should provide the trust-policy statement that must be added to the existing role.

---

# Existing Trust Anchor Mode

For an organization with an existing CA:

```bash
keystone infra cdk init \
    --profile personal \
    --existing-trust-anchor-arn arn:aws:rolesanywhere:...
```

This mode omits trust-anchor creation.

Recommended larger-scale model:

```text
one offline CA
one trust anchor per environment
many Keystone device certificates
one or more Roles Anywhere profiles
device SAN restrictions in IAM policies
```

---

# Generated Outputs

```typescript
new CfnOutput(this, "TrustAnchorArn", {
  value: trustAnchor.attrTrustAnchorArn,
});

new CfnOutput(
  this,
  "RolesAnywhereProfileArn",
  {
    value:
      rolesAnywhereProfile.attrProfileArn,
  },
);

new CfnOutput(this, "RoleArn", {
  value: role.roleArn,
});

new CfnOutput(this, "Region", {
  value: Stack.of(this).region,
});

new CfnOutput(this, "KeystoneKeyId", {
  value: props.keystoneKeyId,
});

new CfnOutput(this, "DeviceSanUri", {
  value: props.deviceSanUri,
});
```

Deployment:

```bash
npm install
npx cdk synth
npx cdk diff
npx cdk deploy \
    --outputs-file cdk-outputs.json
```

Keystone source generation must not automatically run `cdk deploy`.

---

# Profile Synchronization

```bash
keystone infra cdk sync-profile \
    --profile personal \
    --outputs ./cdk-outputs.json
```

The command reads:

* `TrustAnchorArn`;
* `RolesAnywhereProfileArn`;
* `RoleArn`;
* `Region`;
* `KeystoneKeyId`, which is what lets sync refuse an outputs file produced for
  another device.

Pass `--stack-name` when the outputs file holds more than one stack.

It updates the local profile:

```toml
[profiles.personal]
region = "us-east-1"
trust_anchor_arn = "arn:aws:rolesanywhere:..."
roles_anywhere_profile_arn = "arn:aws:rolesanywhere:..."
role_arn = "arn:aws:iam::..."
```

Rules:

* update placeholders automatically;
* preserve matching values;
* reject conflicting existing values;
* require `--force` to overwrite conflicts;
* write the configuration atomically.

---

# CDK Template Strategy

Store versioned embedded templates:

```text
templates/
└── cdk-typescript-v1/
    ├── package.json.tera
    ├── tsconfig.json.tera
    ├── cdk.json.tera
    ├── bin/app.ts.tera
    ├── lib/stack.ts.tera
    ├── test/stack.test.ts.tera
    ├── README.md.tera
    └── keystone.profile.toml.tera
```

Generated metadata:

```json
{
  "generatedBy": "keystone",
  "generatorVersion": "0.1.0",
  "templateVersion": 1,
  "generatedAt": "2026-07-25T23:00:00Z"
}
```

Do not overwrite modified generated files without `--force`.

---

# Generated CDK Tests

The generated CDK app should test that:

* one trust anchor exists;
* the trust anchor uses the expected CA certificate;
* one Roles Anywhere profile exists;
* the profile references the intended role;
* the profile has the configured duration;
* the IAM role trusts `rolesanywhere.amazonaws.com`;
* the role trust policy references the trust anchor;
* the device SAN restriction is present;
* no administrator policy is attached.

Example:

```typescript
template.hasResourceProperties(
  "AWS::RolesAnywhere::Profile",
  {
    Enabled: true,
    DurationSeconds: 3600,
  },
);

template.hasResourceProperties(
  "AWS::IAM::Role",
  {
    AssumeRolePolicyDocument:
      Match.objectLike({
        Statement: Match.arrayWith([
          Match.objectLike({
            Principal: {
              Service:
                "rolesanywhere.amazonaws.com",
            },
          }),
        ]),
      }),
  },
);
```

---

# CLI Types

Illustrative, not authoritative: `crates/keystone-cli/src/cli.rs` is the shipped
definition, and `keystone <command> --help` is the reliable reference for flags.
Known differences from the sketch below: `Test` takes its own `TestArgs`, the CDK
init arguments name a single profile rather than a list, `--duration-seconds` has
no default at the CLI layer (the default is applied downstream), and
`--trust-anchor-name` and `--roles-anywhere-profile-name` exist but are not shown.

```rust
#[derive(clap::Subcommand)]
pub enum Command {
    Init(InitArgs),
    Bootstrap(BootstrapArgs),
    Enroll(EnrollCommand),
    CredentialProcess(CredentialProcessArgs),
    Inspect(ProfileArgs),
    Test(ProfileArgs),
    Doctor(ProfileArgs),
    Rotate(RotateArgs),
    Revoke(ProfileArgs),
    Profiles,
    Infra(InfraCommand),
}
```

```rust
#[derive(clap::Subcommand)]
pub enum InfraCommand {
    Cdk(CdkCommand),
}
```

```rust
#[derive(clap::Subcommand)]
pub enum CdkCommand {
    Init(CdkInitArgs),
    Print(CdkPrintArgs),
    Render(CdkRenderArgs),
    SyncProfile(CdkSyncProfileArgs),
}
```

```rust
#[derive(clap::Args)]
pub struct CdkInitArgs {
    #[arg(long)]
    pub profile: Vec<String>,

    #[arg(long)]
    pub output: PathBuf,

    #[arg(long)]
    pub stack_name: Option<String>,

    #[arg(long)]
    pub role_name: Option<String>,

    #[arg(long)]
    pub existing_trust_anchor_arn:
        Option<String>,

    #[arg(long)]
    pub existing_role_arn: Option<String>,

    #[arg(long)]
    pub policy: Option<PathBuf>,

    #[arg(long)]
    pub managed_policy_arn: Vec<String>,

    #[arg(
        long,
        default_value_t = 3600
    )]
    pub duration_seconds: u32,

    #[arg(long)]
    pub force: bool,
}
```

---

# Logging and Redaction

Safe log fields:

* profile name;
* region;
* role ARN;
* certificate fingerprint prefix;
* certificate expiration;
* request start and completion;
* HTTP status;
* AWS request ID;
* credential expiration.

Never log:

* secret access keys;
* session tokens;
* authorization headers;
* opaque Secure Enclave key references;
* CA private keys;
* complete signed requests in normal operation.

Debug signing output should require:

```bash
keystone credential-process \
    --profile personal \
    --debug-signing
```

Redaction is on by default; `--redact false` widens the output to the full
certificate headers, which are public. Authorization signatures and credentials
stay redacted either way.

---

# Error Model

Illustrative, not authoritative: `crates/keystone-core/src/error.rs` is the actual
enum. It is `#[non_exhaustive]`, several of these variants carry a `String` of
context that is elided here, and it has grown variants this sketch does not list
(`SecureEnclave`, `InvalidCertificate`, `UnknownProfile`, `ProfileIncomplete`,
`Io`, `Other`). What matters below is the *shape* — one variant per failure a user
can act on, each with a message that names the next step.

```rust
#[derive(Debug, thiserror::Error)]
pub enum KeystoneError {
    #[error("Secure Enclave is not available")]
    SecureEnclaveUnavailable,

    #[error("Secure Enclave key could not be restored")]
    KeyUnavailable,

    #[error(
        "certificate does not match the Secure Enclave public key"
    )]
    CertificateKeyMismatch,

    #[error("certificate expired at {0}")]
    CertificateExpired(OffsetDateTime),

    #[error("certificate is not yet valid")]
    CertificateNotYetValid,

    #[error("certificate chain is invalid")]
    InvalidCertificateChain,

    #[error("required Keystone URI SAN is missing")]
    MissingDeviceSan,

    #[error("invalid Keystone configuration: {0}")]
    InvalidConfiguration(String),

    #[error(
        "IAM Roles Anywhere rejected the request: {status} {code}"
    )]
    RolesAnywhereRejected {
        status: u16,
        code: String,
    },

    #[error("system clock may be incorrect")]
    ClockSkew,

    #[error("temporary credential response was malformed")]
    InvalidCredentialResponse,

    #[error("network request failed")]
    Network(#[source] reqwest::Error),
}
```

---

# Testing Strategy

## Unit tests

Test:

* configuration parsing;
* file permission validation;
* certificate parsing;
* public-key matching;
* URI SAN extraction;
* certificate serial conversion;
* canonical URI generation;
* canonical query generation;
* canonical header normalization;
* signed-header ordering;
* request-body hashing;
* credential scope;
* string-to-sign generation;
* certificate header encoding;
* authorization-header generation;
* credential response parsing;
* cache expiration;
* CDK output parsing.

## Golden AWS signing tests

Use:

* fixed software P-256 key;
* fixed certificate;
* fixed timestamp;
* fixed Region;
* fixed request body;
* fixed ARNs.

Record:

* canonical request;
* canonical request hash;
* string to sign;
* signed-header list;
* authorization-header structure.

ECDSA may be nondeterministic, so verify signatures cryptographically rather than requiring identical signature bytes.

## Differential tests

Compare Keystone with the official AWS helper using a software key accessible to both.

Compare all pre-signature artifacts:

* request body;
* canonical request;
* scope;
* string to sign;
* certificate headers.

## Secure Enclave integration tests

On real Apple Silicon hardware:

1. Generate an unattended key.
2. Sign without a UI prompt.
3. Restart the process.
4. Restore and sign again.
5. Lock the Mac.
6. Test expected accessibility behavior.
7. Reboot before first unlock.
8. Confirm signing fails.
9. Log in.
10. Confirm signing succeeds.

## PKI tests

* generated CA validates as a CA;
* leaf validates against generated CA;
* leaf cannot sign certificates;
* leaf key matches the Secure Enclave key;
* incorrect key is rejected;
* incorrect SAN is rejected;
* expired certificate is rejected;
* malformed chain is rejected;
* no CA private key appears in the output tree.

## AWS integration tests

Against a dedicated account:

* valid identity succeeds;
* expired certificate fails;
* wrong CA fails;
* wrong trust anchor fails;
* wrong profile fails;
* wrong role fails;
* modified body fails;
* modified signed header fails;
* stale timestamp fails;
* unauthorized SAN fails;
* returned credentials call `sts:GetCallerIdentity`;
* disabled trust anchor prevents new sessions.

## CDK tests

* synth succeeds;
* expected resources exist;
* external CA bundle is embedded correctly;
* IAM role has no default admin policy;
* SAN restriction is present;
* outputs have expected names;
* `sync-profile` handles conflicts safely.

---

# Implementation Plan

All phases below have shipped. Kept as a record of the intended order; the phase
numbering is this document's own, not an external tracker's, and the code no
longer refers to it — a comment that says "the Phase 1 deliverable" tells a reader
nothing once every phase is done, so those comments now name what they actually
guard.

## Phase 0: AWS protocol spike

Implement Roles Anywhere using:

* a software P-256 key;
* a test X.509 certificate;
* the external CA model.

Compare the request against the official AWS helper.

Deliverable:

```text
software key → CreateSession → temporary credentials
```

## Phase 1: Secure Enclave signer

Replace the software signer with `cryptokit-rs`.

Deliverable:

```text
Secure Enclave key → CreateSession
```

Confirm unattended behavior.

## Phase 2: Local identity

Implement:

```text
keystone init
keystone inspect
keystone doctor
```

## Phase 3: Ephemeral CA bootstrap

Implement:

```text
keystone bootstrap --ca-mode ephemeral
```

Include:

* self-signed CA;
* leaf issuance;
* URI SAN;
* no persisted CA key;
* bootstrap manifest.

## Phase 4: Credential process

Implement:

```text
keystone credential-process
keystone test
```

Document AWS shared-config integration.

## Phase 5: CDK generation

Implement:

```text
keystone infra cdk init
keystone infra cdk print
keystone infra cdk sync-profile
```

## Phase 6: Reliability

Add:

* credential cache;
* interprocess locking;
* clock diagnostics;
* certificate-expiration warnings;
* retry policy;
* atomic configuration updates.

## Phase 7: Rotation

Implement:

```text
keystone rotate
keystone revoke
```

---

# Minimum Viable Product

The MVP should provide:

```text
keystone bootstrap
keystone inspect
keystone credential-process
keystone test
keystone doctor

keystone infra cdk init
keystone infra cdk sync-profile
```

The MVP may:

* support Apple Silicon only;
* support the standard AWS partition only;
* use one identity per profile;
* omit persistent credential caching — in the event this was implemented, as a
  mode-0600 JSON cache;
* create one ephemeral CA per identity;
* create a new IAM role rather than modifying an existing role — `--existing-role-arn`
  references one without modifying it.

The MVP must not:

* export the Secure Enclave private key;
* write the CA private key to disk;
* silently use a software identity;
* require Touch ID for each credential refresh;
* print credentials outside `credential-process`;
* attach administrator permissions;
* disable TLS validation;
* automatically deploy CDK infrastructure.

---

# Example End-to-End Workflow

## Bootstrap local identity and certificate

```bash
keystone bootstrap \
    --profile personal \
    --ca-mode ephemeral \
    --device-name example-laptop \
    --leaf-validity 5y \
    --ca-validity 10y \
    --generate-cdk ./keystone-infra
```

## Review generated infrastructure

```bash
cd keystone-infra
npm install
npx cdk synth
npx cdk diff
```

## Deploy

```bash
npx cdk deploy \
    --outputs-file cdk-outputs.json
```

## Synchronize the Keystone profile

```bash
keystone infra cdk sync-profile \
    --profile personal \
    --outputs ./cdk-outputs.json
```

## Test IAM Roles Anywhere

```bash
keystone test --profile personal
```

## Configure AWS tooling

```ini
[profile keystone-personal]
credential_process = /usr/local/bin/keystone credential-process --profile personal
region = us-east-1
```

## Verify

```bash
AWS_PROFILE=keystone-personal \
    aws sts get-caller-identity
```

---

# Key Design Decisions

## Keystone is standalone

Keystone is not tied to any particular system and can be used by any application or developer workflow.

## Hardware-backed identity

The long-lived private key is device-bound and non-exportable.

## IAM Roles Anywhere

Keystone uses AWS’s existing X.509 workload identity service rather than operating a custom OIDC broker.

## External ephemeral CA by default

A one-shot CA avoids AWS Private CA cost and avoids running permanent PKI infrastructure.

## One CA per device for small installations

The trust anchor becomes the device revocation switch.

For larger deployments, use a shared offline CA and device-specific certificates.

## No biometric prompt for routine use

The default identity is suitable for background credential refresh.

Higher-privilege profiles may later support user-presence keys.

## Standard `credential_process`

Applications need no Keystone-specific AWS SDK integration.

## Official AWS canonicalization

Keystone ports or reuses the official Roles Anywhere helper’s signing behavior.

## CDK generation, not automatic deployment

Keystone emits auditable infrastructure source and leaves deployment under explicit user control.

## No silent fallback

If hardware signing fails, Keystone fails closed.
