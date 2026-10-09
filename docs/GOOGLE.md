# Google service-account tokens (Unix)

`keystone google-token --profile chromebook` uses an enrolled hardware identity
to obtain AWS IAM Roles Anywhere credentials, exchanges a signed AWS assertion
with Google STS, and calls IAM Credentials `generateAccessToken`. The command
prints one JSON document containing the final scoped OAuth access token. No
Google private key or human refresh token is needed by the service.

All account IDs, project IDs, roles, device IDs, service accounts, and paths in
this guide and [google/](google/) are **examples**. Replace them with values from
your deployment before using any configuration or command. In particular,
`123456789012` is AWS's sample account ID, not an account to trust.

## AWS trust and profile

Start with an existing Keystone profile whose device key and certificate can
sign for IAM Roles Anywhere. Create a dedicated IAM role with only the
permissions your Google integration needs. The sample
[trust policy](google/aws-trust.json) restricts assumption to one account, trust
anchor, and Keystone device URI SAN; replace all three. The sample
[Roles Anywhere profile](google/aws-profile.json) allows only that role. Map the
certificate's `x509SAN` `URI` attribute using `put-attribute-mapping` so the SAN
condition can be evaluated.

[setup-cloud.sh](google/setup-cloud.sh) shows the AWS and Google commands. It is
an example, not a deployment script: update the referenced JSON and every
sample identifier before enabling it. Resource creation is not an upsert; inspect
existing resources before changing their trust.

Add a separate Keystone profile for the Google exchange. It can reuse the
existing hardware identity and its issuer metadata while naming the dedicated
role and Roles Anywhere profile:

```toml
[profiles.chromebook]
# Copy the key, certificate, trust anchor, and issuer fields from an enrolled
# profile, then set the role and profile ARNs for this integration.
role_arn = "arn:aws:iam::123456789012:role/ExampleChromebookRole"
roles_anywhere_profile_arn = "arn:aws:rolesanywhere:us-east-2:123456789012:profile/EXAMPLE"
role_session_name = "example-device"

[profiles.chromebook.google]
audience = "//iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/keystone-example/providers/aws-example-device"
service_account = "chromebook-control@example-project.iam.gserviceaccount.com"
scopes = ["https://www.googleapis.com/auth/admin.directory.device.chromeos"]
```

Keep Keystone's directory owner-only (0700) and its configuration file mode
0600. The command requires a complete AWS profile and does not honor
`--allow-unsafe-permissions`. Callers cannot override the configured Google
audience, service account, or scopes on the command line.

## Google trust

Enable the IAM, Resource Manager, IAM Credentials, STS, and application APIs in
your Google project. Create a Workload Identity Pool with an AWS provider that
accepts only the intended AWS account and assumed role. The sample provider
condition checks the exact account, a role ARN prefix ending in `/`, and the
mapped role name. Grant `roles/iam.workloadIdentityUser` on the dedicated
service account to the matching pool principal set. Avoid project-wide token
creator or admin grants.

The example [consumer configuration](google/chromebook-workload-identity.json)
uses the same audience and service account as the Keystone profile. Replace its
absolute executable and home paths with the installed paths. The example
[Rust adapter](google/keystone_credentials.rs) is for a `google-cloud-auth`
1.16.0 consumer; update its fixed policy constants and integrate it explicitly
before that SDK's `external_account` branch. A Keystone OAuth access token is
neither an OIDC ID token nor an AWS subject assertion. The adapter's initial
configuration read must use its nonblocking, no-follow `read_config` helper so
a FIFO cannot stall the consumer before validation.

## Output, cache, and limits

Successful stdout is newline-terminated JSON with `version`, `profile`,
`audience`, `service_account`, `scopes`, `access_token`, `token_type` (`Bearer`),
and `expires_at` (Unix seconds). Treat stdout as secret and capture it through
a private pipe. Errors go to stderr and exit nonzero.

Final tokens are cached under `KEYSTONE_HOME/google-cache/<profile>.json` in an
owner-only directory. AWS assertions and intermediate Google tokens are not
persisted. Keystone starts refresh before expiry, coalesces concurrent callers
with a bounded file lock, and never returns expired credentials after a failed
refresh. The consumer should enforce its own timeout and verify that the token
matches its fixed account, audience, scope, and profile policy.

Local tests cover scope separation, response validation, policy mismatches,
refresh and backoff, concurrent callers, malformed private files, and redacted
diagnostics. Live federation, Directory permissions, and locked-screen renewal
must be verified in each deployment; CI runners do not have the enrolled device
key or cloud trust.

## Protocol references

- [Google AWS federation and trust mapping](https://docs.cloud.google.com/iam/docs/workload-identity-federation-with-other-clouds)
- [AIP-4117 external-account serialization](https://google.aip.dev/auth/4117)
- [STS token exchange](https://docs.cloud.google.com/iam/docs/reference/sts/rest/v1/TopLevel/token)
- [IAM generateAccessToken](https://docs.cloud.google.com/iam/docs/reference/credentials/rest/v1/projects.serviceAccounts/generateAccessToken)
