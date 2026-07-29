# Keystone

Hardware-backed temporary AWS credentials, from the Secure Enclave on macOS or
the TPM on Windows.

## Status

Implemented against [docs/DESIGN.md](docs/DESIGN.md), which remains the
specification, and exercised end to end against a real AWS account: a Secure
Enclave key signs `CreateSession`, IAM Roles Anywhere returns temporary
credentials, and the AWS CLI uses them through `credential_process`. The
account-dependent tests pass; see [Testing](#testing).

Three defects only a real account surfaced, each now regression-tested:

* the generated role's trust policy granted `sts:AssumeRole` alone, so
  `CreateSession` failed with `AccessDenied` after the certificate and signature
  had already been accepted — Roles Anywhere also calls `sts:TagSession` and
  `sts:SetSourceIdentity` whenever the profile maps attributes;
* the request sent the deprecated `sessionName` instead of `roleSessionName`,
  which AWS ignores silently, so CloudTrail named every session after a hash of
  the device public key;
* clock-skew detection looked for wording ("expired", a date) that IAM Roles
  Anywhere does not use — it answers a stale signature with `Invalid signature`.

## Summary

Keystone is a standalone credential helper that exchanges a hardware-backed
device identity for temporary AWS credentials through AWS IAM Roles Anywhere.

The long-lived private key is generated inside the Mac's Secure Enclave, or the
PC's TPM, and is never exported. Keystone uses that key to sign an IAM Roles
Anywhere `CreateSession` request. IAM Roles Anywhere validates the signature and
X.509 certificate, then returns ordinary temporary AWS credentials, which Keystone
emits through the standard AWS `credential_process` contract.

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

Keystone avoids long-lived AWS access keys, exportable private-key files, a
continuously running certificate authority, the recurring cost of AWS Private
CA, and biometric prompts for routine credential refresh.

## Building

Requires a recent Rust toolchain, and hardware with the key store for the target
platform: a Mac with a Secure Enclave, or a PC with a TPM 2.0 enabled in firmware.
There is no software fallback — on a machine without one, every operation reports
that no hardware-backed key store is available.

On macOS the Secure Enclave binding compiles a Swift bridge, so Xcode command line
tools must be installed. On Windows nothing beyond the toolchain is needed; CNG is
part of the OS.

```bash
cargo build --release   # target/release/keystone
```

The Windows build can be checked from macOS without a PC. `x86_64-pc-windows-msvc`
does not work as a cross target here, because `ring` compiles C that needs the
Windows SDK headers; the GNU target does:

```bash
rustup target add x86_64-pc-windows-gnu
brew install mingw-w64
CC_x86_64_pc_windows_gnu=x86_64-w64-mingw32-gcc \
AR_x86_64_pc_windows_gnu=x86_64-w64-mingw32-ar \
  cargo clippy --workspace --all-targets --target x86_64-pc-windows-gnu
```

That checks the code but runs nothing: the TPM tests need a TPM, so they are
compiled only for Windows and must be run there.

## Continuous integration

Two workflows under `.github/workflows`:

* `ci.yml` — formatting, `clippy -D warnings`, and the test suite on macOS and
  Windows runners, plus a `cargo check` against the declared MSRV of 1.88.
* `release.yml` — builds `aarch64-apple-darwin` and `x86_64-pc-windows-msvc`
  binaries, each packaged with a SHA-256 checksum in the format its platform
  opens without extra tools: `.tar.gz` for macOS, `.zip` for Windows. A `v*` tag
  drafts a GitHub release with both archives attached; a manual dispatch produces
  the same archives as run artifacts and publishes nothing.

Neither runner has a Secure Enclave or a TPM, so the hardware tests early-return
and CI never exercises a signing path. That is the fail-closed design observed
from the outside, and it is also the limit of what CI can tell you: a release
binary should be run through `keystone doctor` on real hardware before it is
published, which is why the release is drafted rather than published outright.

No `x86_64-apple-darwin` binary is built, matching the Platform Support section
of the design document — Intel Macs are listed there as possible future support
pending integration testing, and shipping a binary for an untested configuration
would claim more than the project has verified.

## Workflow

```bash
# --device-name also becomes the role session name, so CloudTrail and
# `aws sts get-caller-identity` name this machine rather than a hash of its key.
keystone bootstrap --profile personal --region us-east-1 --ca-mode ephemeral \
    --device-name my-laptop --generate-cdk ./keystone-infra

cd keystone-infra && npm install && npx cdk deploy --outputs-file cdk-outputs.json

keystone infra cdk sync-profile --profile personal --outputs ./cdk-outputs.json
keystone test --profile personal
```

Then in `~/.aws/config`:

```ini
[profile keystone-personal]
credential_process = /usr/local/bin/keystone credential-process --profile personal
region = us-east-1
```

## Layout

| Crate | Contents |
|---|---|
| `keystone-core` | Configuration, the on-disk store, credentials, clock, errors |
| `keystone-macos` | Secure Enclave key generation and signing |
| `keystone-windows` | TPM key generation and signing, via CNG |
| `keystone-win32-sys` | The FFI quarantine: the only crate allowed to use `unsafe` |
| `keystone-pki` | Certificate parsing and validation, the ephemeral CA |
| `keystone-roles-anywhere` | `AWS4-X509-ECDSA-SHA256` signing and the `CreateSession` client |
| `keystone-infra` | CDK project generation and profile sync |
| `keystone-cli` | The `keystone` binary |
| `keystone-tests` | The suites under `tests/` |

## Testing

```bash
cargo test --workspace
```

Everything that can run without external tooling or an AWS account runs by
default, including the hardware tests when the platform's key store is present.
The rest are `#[ignore]`d:

```bash
# The manual procedures: screen-locked and pre-first-unlock signing, and the
# cases that would require changing an AWS account. These print, they do not run.
cargo test -p keystone-tests --test integration_secure_enclave -- --ignored --nocapture
cargo test -p keystone-tests --test integration_aws -- --ignored --nocapture

# The generated CDK project, compiled and synthesized. Runs npm install.
cargo test -p keystone-tests --test integration_cdk -- --ignored

# Against a dedicated AWS account. Read-only: these call CreateSession and
# sts:GetCallerIdentity and create, modify, and delete nothing.
KEYSTONE_AWS_INTEGRATION_PROFILE=personal \
  cargo test -p keystone-tests --test integration_aws -- --ignored --nocapture
```

`tests/fixtures/` holds certificates generated by OpenSSL rather than by
Keystone, so the PKI and golden signing suites check Keystone's output against an
independent implementation. Regenerate them with `tests/fixtures/generate.sh`;
the issuing CA keys are deleted at the end of that script by design.

The two device private keys under `tests/fixtures/` are committed on purpose and
authenticate nothing — the golden suite has to sign fixed bytes the way the
official AWS helper would. Secret scanners flag them. A real Keystone device key
cannot look like this: it is generated inside the Secure Enclave or the TPM and
has no PEM form.

## Documentation

* [Design document](docs/DESIGN.md) — security model, PKI and ephemeral CA
  bootstrap, AWS4-X509 signing, CDK generation, rotation and revocation, and
  testing strategy.

## License

MIT — see [LICENSE](LICENSE).
