# Keystone

Hardware-backed temporary AWS credentials on macOS and Windows, plus a Secure
Enclave SSH agent on macOS.

## Status

The AWS workflow is implemented against [docs/DESIGN.md](docs/DESIGN.md) and
exercised end to end against a real AWS account: a Secure Enclave key signs
`CreateSession`, IAM Roles Anywhere returns temporary credentials, and the AWS CLI uses them through `credential_process`. The
account-dependent tests pass; see [Testing](#testing).

The macOS SSH agent supports dedicated non-exportable P-256 identities, OpenSSH
public-key output, and generated SSH configuration. Listing keys and verifying
signatures have been exercised with `ssh-add` against a real Secure Enclave.
See [SSH workflow](#secure-enclave-ssh-agent-macos).

Three AWS defects only a real account surfaced, each now regression-tested:

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
There is no software fallback: creating or using a hardware identity requires
the corresponding key store. SSH identities require the macOS Secure Enclave;
the Windows TPM backend currently serves the AWS workflow.

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
  binaries, each with a SHA-256 checksum beside it. macOS ships as a `.tar.gz`,
  because a tarball is what preserves the executable bit; Windows ships the
  `keystone.exe` itself, since Windows decides executability by extension and a
  container would only add a step. A `v*` tag drafts a GitHub release with both
  attached; a manual dispatch produces the same files as run artifacts and
  publishes nothing.

Neither runner has a Secure Enclave or a TPM, so the hardware tests early-return
and CI never exercises a signing path. That is the fail-closed design observed
from the outside, and it is also the limit of what CI can tell you: a release
binary should be run through `keystone doctor` on real hardware before it is
published, which is why the release is drafted rather than published outright.

No `x86_64-apple-darwin` binary is built, matching the Platform Support section
of the design document — Intel Macs are listed there as possible future support
pending integration testing, and shipping a binary for an untested configuration
would claim more than the project has verified.

## AWS workflow

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

## Hardware-backed service tokens

Keystone can issue short-lived ES256 JWTs signed by a profile's existing Secure
Enclave or TPM identity. The token contains the device key ID, device URI,
issuer, audience, and issue/expiry times. A service must already trust the
device's public key and verify the signature, issuer, audience, and expiry.

```bash
keystone token \
  --profile robotics \
  --issuer https://auth.example.com \
  --audience https://api.example.com
```

The command prints one JWT and a newline to stdout. `--ttl 5m` is optional;
supported lifetimes are 1 through 15 minutes (default 5 minutes). Issuer and
audience must be absolute HTTPS URLs without credentials or fragments. Their
spelling, including paths and trailing slashes, is preserved in the token.

## KMS-backed reusable CA

For a group that needs to renew or replace device certificates without creating
a new IAM Roles Anywhere trust anchor each time, Keystone can use an existing
AWS KMS asymmetric key as a reusable CA. This differs from `--ca-mode
ephemeral`: the signing authority remains available to administrators, but its
private scalar never leaves KMS. Device keys remain hardware-backed and
non-exportable, and device/student roles need no KMS permission.

Create the KMS key separately with key spec `ECC_NIST_P256`, key usage
`SIGN_VERIFY`, and signing algorithm `ECDSA_SHA_256`. Keystone V1 intentionally
does not create or delete keys, aliases, policies, or grants. Then initialize
the public CA certificate:

```bash
keystone ca init \
    --kms-key arn:aws:kms:us-east-2:123456789012:key/EXAMPLE \
    --region us-east-2 \
    --subject "CN=Keystone Device CA,O=Example" \
    --validity 10y \
    --output ca.pem
```

Create a device identity and CSR on the device, issue it on an administrator
machine, and install the public result back on the device:

```bash
keystone init --profile devices --region us-east-2
keystone enroll csr --profile devices --device-name alice-laptop --output alice.csr

keystone ca issue \
    --kms-key arn:aws:kms:us-east-2:123456789012:key/EXAMPLE \
    --region us-east-2 \
    --ca-certificate ca.pem \
    --csr alice.csr \
    --validity 1y \
    --output alice.pem

keystone enroll install --profile devices --certificate alice.pem --chain ca.pem
```

Both CA commands use the normal AWS credential provider chain. `--aws-profile
<name>` selects a named profile; static access-key arguments are not supported.
The administrator needs only the following key permissions. The algorithm
condition belongs on `kms:Sign`; `kms:GetPublicKey` is separate because that
operation does not accept the `kms:SigningAlgorithm` condition key.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "kms:GetPublicKey",
      "Resource": "arn:aws:kms:us-east-2:123456789012:key/EXAMPLE"
    },
    {
      "Effect": "Allow",
      "Action": "kms:Sign",
      "Resource": "arn:aws:kms:us-east-2:123456789012:key/EXAMPLE",
      "Condition": {
        "StringEquals": { "kms:SigningAlgorithm": "ECDSA_SHA_256" }
      }
    }
  ]
}
```

Only administrators should receive `kms:Sign`. Compromise of a device permits
use of that device's hardware key and may expose already-issued temporary
credentials, but cannot issue another certificate. Compromise of administrator
credentials may permit issuance, without exposing the CA private scalar. Control
of the KMS key is equivalent to compromise of the CA signing authority and
affects every certificate it issued. Losing one device does not affect the CA;
a replacement device can create a new hardware identity and CSR.

## Google service-account tokens (Unix)

`keystone google-token --profile chromebook` uses a named profile's fixed Google
policy to exchange renewable AWS credentials through Workload Identity Federation
and return a scoped service-account OAuth token. Tokens are cached privately;
concurrent refreshes are coalesced and failures back off. No Google private key
or Workspace-user impersonation is used. Stdout contains a secret token document.

See [Google setup and consumer handoff](docs/GOOGLE.md) for cloud trust, the Rust
consumer adapter, deployment state, and the remaining AWS administrator setup.

## Secure Enclave SSH agent (macOS)

Create a dedicated, non-exportable P-256 SSH key and start its agent:

```sh
keystone ssh init my-keystone-id
keystone ssh agent my-keystone-id
```

`init` prints an OpenSSH public key (`ecdsa-sha2-nistp256 AAAA…
my-keystone-id@keystone`) and writes `identity.pub` and `ssh_config` under
`~/Library/Application Support/Keystone/ssh/my-keystone-id/` by default.
Repeating `init` preserves the key. Copy the public key to your server's `authorized_keys` or your Git hosting
account. No AWS profile, certificate, or region is required.

Print the public key again with `keystone ssh public-key my-keystone-id`.

Print the generated config with `keystone ssh config my-keystone-id`. It contains:

```sshconfig
Host *
    IdentityAgent "/Users/YOUR_USER/Library/Application Support/Keystone/ssh/my-keystone-id/agent.sock"
    IdentityFile "/Users/YOUR_USER/Library/Application Support/Keystone/ssh/my-keystone-id/identity.pub"
    IdentitiesOnly yes
```

With the agent running, connect from another terminal:

```sh
ssh -F "$HOME/Library/Application Support/Keystone/ssh/my-keystone-id/ssh_config" user@host
```

Alternatively, copy these settings into a matching `Host` block in `~/.ssh/config`. `IdentityAgent` takes only the socket
path; `IdentityFile` selects the public key. The generated config is a separate
file and does not modify your existing SSH settings. Paths are absolute and
quoted to support spaces. `--home` / `KEYSTONE_HOME` also apply to SSH commands;
use the same value for initialization and the agent.

The agent runs in the foreground until stopped; automatic login startup is not
installed. One process serves one identity. Its directory is mode 0700 and the
socket is mode 0600. A process lock prevents duplicate agents, and restarting
replaces a stale socket. To check interoperability:

```sh
keystone_ssh_dir="$HOME/Library/Application Support/Keystone/ssh/my-keystone-id"
SSH_AUTH_SOCK="$keystone_ssh_dir/agent.sock" ssh-add -L
SSH_AUTH_SOCK="$keystone_ssh_dir/agent.sock" ssh-add -T "$keystone_ssh_dir/identity.pub"
```

Keys use Keystone's existing device-only, after-first-unlock policy with no
Touch ID prompt. The on-disk identity contains an opaque, device-bound Secure
Enclave reference, never an exportable private key. Processes running as your
user can request signatures while the agent is available. Only SSH list and
sign requests are supported; key import/removal, agent locking, and destination
constraints are unsupported. Avoid agent forwarding unless you intend to grant
the remote host signing access. There is no software-key fallback on unsupported
hardware or platforms. SSH ECDSA encoding follows
[RFC 5656](https://www.rfc-editor.org/rfc/rfc5656).

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
| `keystone-cli` | The `keystone` binary, including the macOS SSH agent |
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
