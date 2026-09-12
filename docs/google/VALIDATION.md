# Validation record — 2026-09-12

- Full `cargo test --workspace --locked`: passed, including AWS/SSH regressions;
  existing ignored account/manual tests stayed ignored.
- Google suite after final fixes: 11 passed.
- `cargo clippy --workspace --all-targets --locked -- -D warnings`: passed.
- `cargo fmt --all --check`, `git diff --check`, setup shell syntax: passed.
- Consumer adapter compiled in an isolated temporary crate against
  `google-cloud-auth = 1.16.0` using the home repository's lockfile. No home
  repository files were changed.
- Public test assertion signature agrees with Python botocore SigV4Auth.
- Release build succeeded. The installed toolchain's optional debug stripping
  emitted a missing `libLLVM.dylib` warning; binary build and execution succeeded.
- Release `doctor --profile personal`: all 16 checks passed, including hardware
  key restore, noninteractive signature, certificate checks and live AWS
  CreateSession. This was run with the screen unlocked, outside the sandbox.
- Self-review covered fixed endpoints, signed audience, intermediate/final scope
  separation, cache binding and lock lifetime, deadlines, response redaction,
  private-file checks, consumer contract and existing-profile compatibility.
  Review corrections included rejecting newly minted tokens already inside the
  refresh margin and explicitly documenting the AWS SAN attribute mapping.
  No independent agent review was performed.
- Google provider was read back as ACTIVE with the exact intended condition;
  service-account policy was read back with only the intended WIF binding.

Not yet verified: real Google token minting, Directory inventory/device ID,
Workspace role/OU authorization, live Google renewal after an hour or locked
screen, reboot before first login, and Windows Google support. The new dedicated
AWS role/profile could not be created under the current non-admin AWS identity.
See ../GOOGLE.md for exact remaining setup and consumer commissioning steps.

The local consumer configuration is staged only. Binary installation/commit
identity are recorded in the external handoff after the signed commit is made.

## Independent review follow-up

A subagent reviewed commit f28e94c and found one P2 availability defect:
blocking file opens could hang on a FIFO before rejecting nonregular files.
Its release-binary reproduction remained blocked after 21 seconds.

Fixed Keystone and the staged consumer reader with nonblocking, no-follow
opens followed by handle-based regular-file validation. The reviewer rechecked
the fix and reported no new defects. Targeted Google tests now pass 12 cases;
the staged adapter's FIFO regression also passes against auth SDK 1.16.0.
The reviewer noted that the home consumer's initial pre-dispatch config read
needs the same treatment; the handoff now explicitly uses the public safe reader
there. No home repository files or cloud state were changed during this review.
