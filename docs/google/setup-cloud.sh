#!/bin/sh
# Example only. Replace every sample identifier in docs/google/aws-trust.json
# and docs/google/aws-profile.json, then supply matching values below.
# Inspect existing resources before creating or changing cloud trust.
set -eu

: "${KEYSTONE_AWS_ADMIN_PROFILE:?Set an AWS administrator CLI profile}"
: "${KEYSTONE_AWS_ACCOUNT_ID:?Set the AWS account ID}"
: "${KEYSTONE_ROLE_NAME:?Set the dedicated IAM role name}"
: "${KEYSTONE_GCP_PROJECT_ID:?Set the Google project ID}"
: "${KEYSTONE_GCP_PROJECT_NUMBER:?Set the Google project number}"
: "${KEYSTONE_GOOGLE_SERVICE_ACCOUNT:?Set the Google service-account email}"
: "${KEYSTONE_POOL_ID:?Set the Workload Identity Pool ID}"
: "${KEYSTONE_PROVIDER_ID:?Set the AWS provider ID}"

if [ "$KEYSTONE_AWS_ACCOUNT_ID" = 123456789012 ] || \
   grep -Eq '123456789012|ExampleChromebookRole|0123456789abcdef' \
     docs/google/aws-trust.json docs/google/aws-profile.json; then
  echo 'Replace the sample AWS identifiers in the JSON and environment before running.' >&2
  exit 1
fi

aws iam create-role --role-name "$KEYSTONE_ROLE_NAME" \
  --assume-role-policy-document file://docs/google/aws-trust.json \
  --description 'Keystone Google federation example' \
  --max-session-duration 3600 --profile "$KEYSTONE_AWS_ADMIN_PROFILE"

keystone_google_profile_id=$(aws rolesanywhere create-profile \
  --cli-input-json file://docs/google/aws-profile.json \
  --region us-east-2 --profile "$KEYSTONE_AWS_ADMIN_PROFILE" \
  --query profile.profileId --output text)
aws rolesanywhere put-attribute-mapping --profile-id "$keystone_google_profile_id" \
  --certificate-field x509SAN --mapping-rules '[{"specifier":"URI"}]' \
  --region us-east-2 --profile "$KEYSTONE_AWS_ADMIN_PROFILE"
aws rolesanywhere get-profile --profile-id "$keystone_google_profile_id" \
  --region us-east-2 --profile "$KEYSTONE_AWS_ADMIN_PROFILE"

gcloud services enable iam.googleapis.com cloudresourcemanager.googleapis.com \
  iamcredentials.googleapis.com sts.googleapis.com admin.googleapis.com \
  --project="$KEYSTONE_GCP_PROJECT_ID"
gcloud iam workload-identity-pools create "$KEYSTONE_POOL_ID" \
  --location=global --project="$KEYSTONE_GCP_PROJECT_ID" \
  --display-name='Keystone example'
gcloud iam workload-identity-pools providers create-aws "$KEYSTONE_PROVIDER_ID" \
  --location=global --workload-identity-pool="$KEYSTONE_POOL_ID" \
  --account-id="$KEYSTONE_AWS_ACCOUNT_ID" \
  --attribute-mapping="google.subject=assertion.arn,attribute.account=assertion.account,attribute.aws_role=assertion.arn.extract('assumed-role/{role_name}/')" \
  --attribute-condition="assertion.account == '$KEYSTONE_AWS_ACCOUNT_ID' && assertion.arn.startsWith('arn:aws:sts::$KEYSTONE_AWS_ACCOUNT_ID:assumed-role/$KEYSTONE_ROLE_NAME/') && attribute.aws_role == '$KEYSTONE_ROLE_NAME'" \
  --project="$KEYSTONE_GCP_PROJECT_ID"
gcloud iam service-accounts add-iam-policy-binding \
  "$KEYSTONE_GOOGLE_SERVICE_ACCOUNT" --project="$KEYSTONE_GCP_PROJECT_ID" \
  --member="principalSet://iam.googleapis.com/projects/$KEYSTONE_GCP_PROJECT_NUMBER/locations/global/workloadIdentityPools/$KEYSTONE_POOL_ID/attribute.aws_role/$KEYSTONE_ROLE_NAME" \
  --role=roles/iam.workloadIdentityUser
