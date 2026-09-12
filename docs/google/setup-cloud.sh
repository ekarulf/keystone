#!/bin/sh
# Run from the repository root. Supply an AWS admin profile; no role grants are
# added to KeystonePersonal, backup, or Bedrock. Creation is intentionally not
# an upsert: existing resources require inspection before any trust is changed.
set -eu
: "${KEYSTONE_AWS_ADMIN_PROFILE:?Set this to an AWS administrator CLI profile}"
aws iam create-role --role-name KeystoneChromebookGoogle \
  --assume-role-policy-document file://docs/google/aws-trust.json \
  --description 'Keystone Mac mini Google Chromebook federation' \
  --max-session-duration 3600 --profile "$KEYSTONE_AWS_ADMIN_PROFILE"
keystone_chromebook_profile_id=$(aws rolesanywhere create-profile --cli-input-json file://docs/google/aws-profile.json \
  --region us-east-2 --profile "$KEYSTONE_AWS_ADMIN_PROFILE" --query profile.profileId --output text)
aws rolesanywhere put-attribute-mapping --profile-id "$keystone_chromebook_profile_id" \
  --certificate-field x509SAN --mapping-rules '[{"specifier":"URI"}]' \
  --region us-east-2 --profile "$KEYSTONE_AWS_ADMIN_PROFILE"
aws rolesanywhere get-profile --profile-id "$keystone_chromebook_profile_id" \
  --region us-east-2 --profile "$KEYSTONE_AWS_ADMIN_PROFILE"
# Record the returned profileArn in [profiles.chromebook]. No AWS permission
# policy is attached: GetCallerIdentity needs no workload permissions.

# The following Google steps were completed on 2026-09-12. On a new project,
# run them once; on this project inspect instead of repeating create commands.
gcloud services enable iam.googleapis.com cloudresourcemanager.googleapis.com \
  iamcredentials.googleapis.com sts.googleapis.com admin.googleapis.com --project=karulf-home
gcloud iam workload-identity-pools create keystone-home --location=global \
  --project=karulf-home --display-name='Keystone home'
gcloud iam workload-identity-pools providers create-aws aws-mac-mini \
  --location=global --workload-identity-pool=keystone-home --account-id=117915346373 \
  --attribute-mapping="google.subject=assertion.arn,attribute.account=assertion.account,attribute.aws_role=assertion.arn.extract('assumed-role/{role_name}/')" \
  --attribute-condition="assertion.account == '117915346373' && assertion.arn.startsWith('arn:aws:sts::117915346373:assumed-role/KeystoneChromebookGoogle/') && attribute.aws_role == 'KeystoneChromebookGoogle'" \
  --project=karulf-home
gcloud iam service-accounts add-iam-policy-binding \
  chromebook-control@karulf-home.iam.gserviceaccount.com --project=karulf-home \
  --member='principalSet://iam.googleapis.com/projects/893698030930/locations/global/workloadIdentityPools/keystone-home/attribute.aws_role/KeystoneChromebookGoogle' \
  --role=roles/iam.workloadIdentityUser
