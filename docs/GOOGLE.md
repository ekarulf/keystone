# Google authentication for Chromebook management

Keystone's Unix `google-token --profile chromebook` command exchanges renewable
Roles Anywhere credentials for a Google STS token, then calls IAM Credentials
`generateAccessToken`. It emits one JSON document with the **final** scoped
service-account OAuth token. There are no Google private keys, user subjects,
human refresh tokens in the daemon, OIDC issuers, metadata emulators, or local
HTTP credential services.

## Policy and source identity

This integration uses AWS account `117915346373`, region `us-east-2`, and a new
role `arn:aws:iam::117915346373:role/KeystoneChromebookGoogle`. The role is
**not yet created**: the current `keystone-personal` session was denied
`iam:CreateRole` and `iam:PassRole`. An AWS administrator must run the AWS
commands in [google/setup-cloud.sh](google/setup-cloud.sh), using the checked-in
trust and profile documents. Do not rerun the already-completed Google create
commands. No workload permission policy needs to be attached to this AWS role.

The role uses the existing personal trust anchor
`arn:aws:rolesanywhere:us-east-2:117915346373:trust-anchor/5184399a-5e77-4043-90fc-af7b6287468d`
and the device SAN `urn:keystone:device:7bd0ce3fd8f6c4574113c556e5dbe5f0`.
This source was discovered from local Keystone configuration and verified by
reading the existing AWS role trust. It does not reuse backup or Bedrock roles.
The new role's assumption policy checks both the exact anchor/account and device
SAN. Its Roles Anywhere profile must allow only this one role and map `x509SAN` /
`URI` using `put-attribute-mapping`, as shown in the setup script.

Once AWS returns the new Roles Anywhere profile ARN, copy the existing
`[profiles.personal]` and `[profiles.personal.issuer]` sections to new sections
`[profiles.chromebook]` and `[profiles.chromebook.issuer]`. Preserve their key ID,
certificate/CA fingerprints, anchor, region, and issuer metadata. Change only:

```toml
role_arn = "arn:aws:iam::117915346373:role/KeystoneChromebookGoogle"
roles_anywhere_profile_arn = "REPLACE_WITH_CREATED_PROFILE_ARN"
role_session_name = "chromebook-mac-mini"
```

Append this policy to the new profile:

```toml
[profiles.chromebook.google]
audience = "//iam.googleapis.com/projects/893698030930/locations/global/workloadIdentityPools/keystone-home/providers/aws-mac-mini"
service_account = "chromebook-control@karulf-home.iam.gserviceaccount.com"
scopes = ["https://www.googleapis.com/auth/admin.directory.device.chromeos"]
```

Keep `config.toml` mode 0600 and Keystone's directory mode 0700, owned by the
service UID. Write configuration atomically. Existing AWS/SSH profiles need no
changes. Google requires a fully configured AWS profile and does not honor
`--allow-unsafe-permissions`. The Google command accepts no audience, service
account or scope overrides. Other profiles without Google policy cannot mint
Google tokens through this command.

## Google cloud state verified 2026-09-12

- `karulf-home` project number: `893698030930`.
- Existing service account verified; unique ID: `110557116490999850521`.
- Admin SDK (`admin.googleapis.com`) was already enabled.
- Enabled IAM, Resource Manager, IAM Credentials and STS APIs.
- Created pool `keystone-home`, provider `aws-mac-mini`.
- Provider condition requires account `117915346373` AND the assumed-role ARN
  prefix `arn:aws:sts::117915346373:assumed-role/KeystoneChromebookGoogle/` AND
  the exact mapped role name. The trailing slash prevents role-prefix confusion;
  session suffixes may change without changing identity grants.
- Granted `roles/iam.workloadIdentityUser` only on the existing dedicated service
  account to
  `principalSet://iam.googleapis.com/projects/893698030930/locations/global/workloadIdentityPools/keystone-home/attribute.aws_role/KeystoneChromebookGoogle`.

Reproduce the mapping and commands with [setup-cloud.sh](google/setup-cloud.sh).
No project-wide token creator/admin role was added. No Workspace role, OU scope,
or Locate Chromebook permission was changed. The user-reported direct Workspace
role assignment remains unverified until a successful Directory request.
Homebrew installed `gcloud-cli`; `erik@karulf.com` completed the one-time admin
login. That CLI session is separate from the daemon's credentials.

## Consumer adapter and configuration

The pinned `google-cloud-auth` 1.16.0 AWS source reads environment credentials or
instance metadata, not `credential_process`. Programmatic subject tokens are
supported, but would leave final target/scope selection to the consumer.
Keystone instead owns both exchange stages and the final cache. Thus the
existing `external_account::Builder` is **not** compatible with this protocol.
Do not label an access token as an OIDC `id_token` or external AWS assertion.

[google/keystone_credentials.rs](google/keystone_credentials.rs) is the minimal
consumer adapter, checked against the actual pinned Rust SDK. Copy it into
`crates/chromebook-control/src/`, add `mod keystone_credentials;`, and add an
explicit branch in `GoogleAdmin::workload_identity` before the existing
external-account builder. Replace its initial `std::fs::read(path)` as well;
that read happens before dispatch and otherwise can block on a FIFO:

```rust
let config: Value = serde_json::from_slice(&keystone_credentials::read_config(path)?)?;
if config["type"] == "keystone_google" {
    return Self::new(keystone_credentials::credentials(path, service_account)?, customer);
}
```

Retain the old `external_account` branch's exact target check. The new adapter
independently checks the fixed account, audience, scope, profile, helper path,
home path, file trust and every token response. It implements the SDK's
`AccessTokenCredentialsProvider`; `GoogleAdmin` can keep calling
`credentials.access_token()` with its existing timeout. Add Tokio features
`process` and `io-util` if not already enabled, and `rustix = { version = "1",
features = ["fs"] }` for safe file opening. No shell is invoked. Stderr and
malformed responses are never included in application errors.

The complete non-secret configuration is
[google/chromebook-workload-identity.json](google/chromebook-workload-identity.json).
Install it as `/opt/home.karulf.com/etc/chromebook-workload-identity.json`, owned
by the service UID or root, mode 0600, with no untrusted writers on parent paths.
**This file is staged, not installed.** Its type is deliberately
`keystone_google`, so an unpatched consumer rejects it rather than attempting
an incorrect external-account flow. The home repository was not modified.

Keep the home configuration:

```toml
customer_id = "C01jek4ft"
service_account = "chromebook-control@karulf-home.iam.gserviceaccount.com"
workload_identity_config = "/opt/home.karulf.com/etc/chromebook-workload-identity.json"
devices = []
```

Set `CHROMEBOOK_CONFIG` in home-automation's LaunchAgent to the TOML path and
preserve its existing `HOME_DB`. The adapter uses absolute helper/home paths;
no AWS environment snapshots, `AWS_PROFILE`, `GOOGLE_APPLICATION_CREDENTIALS`,
PATH additions, token-source files, or new refresher LaunchAgents are needed.
The existing LaunchAgent runs as `ekarulf`; no unrelated service was restarted.

## Process protocol and renewal

Successful stdout is newline-terminated JSON with `version` (1), `profile`,
`audience`, `service_account`, `scopes`, `access_token`, `token_type` (`Bearer`),
and `expires_at` (Unix seconds). Stdout is secret; capture it through a private
pipe, never a log or browser. Errors use stderr and nonzero exit. The consumer
maps acquisition failures to transient errors, invalid configuration/protocol
to permanent errors, and must preserve the worker's bounded retry behavior.

Final tokens live in `KEYSTONE_HOME/google-cache/<profile>.json`, mode 0600,
inside an owner-only 0700 directory. No AWS assertion or intermediate Google
token is persisted. A token refresh constructs a new timestamped AWS SigV4
`GetCallerIdentity` assertion with a signed `x-goog-cloud-target-resource`
header; its short replay window is never confused with the AWS session expiry.
The JSON assertion is URL-encoded once inside the STS JSON request per AIP-4117.
STS uses cloud-platform scope; IAM uses only the configured final scopes.

The cache is bound to the complete AWS/Google profile, including hardware key
and trust configuration. An exclusive file lock coalesces concurrent processes;
waits are bounded by an 18-second overall exchange budget. AWS acquisition runs
in a child with a ten-second cap; Google HTTP calls share the remaining budget.
Google redirects/proxies are disabled, HTTPS hosts are fixed, and response
sizes are capped. Refresh begins 60 seconds before actual expiry. A failed
refresh saves a five-second backoff, discards the old token, and never returns
expired credentials. This also bounds repeated permanent failures without
hiding recovery after trust is restored. The consumer kills its helper on a
20-second timeout. Cached tokens may remain usable until expiry after remote
trust revocation, as with any already-issued OAuth token.

Private files are opened nonblocking and no-follow and checked through their handles for owner,
mode, regular-file type and hard links; ancestors are checked for symlinks and
untrusted writers. Cache updates are atomic. Existing AWS storage continues to
use Keystone's existing permission model; this change does not claim to repair
all existing AWS storage races. Secret buffers are zeroized where practical;
HTTP/JSON libraries can leave transient copies in memory. Debug output redacts
tokens and failures omit remote bodies and raw transport errors.

**Same-UID processes are not isolated.** They can invoke Keystone, read the
cache, or edit their own policy. The named policy limits this helper interface,
not a malicious process that already controls the service account's macOS UID.
Use separate OS users if that stronger boundary is needed.

## Verification and limitations

Local tests cover STS/IAM scope separation and response validation, profile and
policy mismatches, actual-expiry refresh across repeated invocations, renewed
assertions after AWS rotation, 12 concurrent callers, bounded locks, shared
failure backoff/recovery, malformed/unsafe files, missing/expired credentials,
and redacted diagnostics. The signature fixture matches Python botocore's
independent SigV4 signer. The full workspace tests (including AWS/SSH regression
suites), formatting and Clippy are required before committing.

Live Google token minting and a read-only Directory lookup remain blocked on
creation of the dedicated AWS role/profile and installation of local policy.
Owen's device ID for serial `NXJL7AA001534006C42000` is therefore **not yet known**.
Do not claim the Chromebook feature is live. After the home agent installs the
adapter/config, run its read-only `--chromebook-list` with `HOME_DB` and
`CHROMEBOOK_CONFIG`, while no Chromebook worker holds its exclusive lock.
Do not disable, locate, or otherwise control a device for this verification.

The hardware identity uses `after-first-unlock`, designed to sign while the
screen is locked after first login. Its ephemeral-CA certificate expires
`2031-07-29T01:15:25Z` and cannot renew itself; rotation needs a new certificate
and trust anchor. Session renewal requires no routine human Google login.
Locked-screen Google renewal and recovery before first login after reboot
have **not** been demonstrated. This is a per-user LaunchAgent, so it does not
start before that user's login; do not claim unattended pre-login recovery.

## Protocol references

- [Google AWS federation and trust mapping](https://docs.cloud.google.com/iam/docs/workload-identity-federation-with-other-clouds)
- [AIP-4117 external-account serialization](https://google.aip.dev/auth/4117)
- [STS token exchange](https://docs.cloud.google.com/iam/docs/reference/sts/rest/v1/TopLevel/token)
- [IAM generateAccessToken](https://docs.cloud.google.com/iam/docs/reference/credentials/rest/v1/projects.serviceAccounts/generateAccessToken)

These were checked alongside the installed `google-cloud-auth` 1.16.0 source.
