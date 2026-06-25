#!/bin/bash
# =============================================================================
# Remediation: Clean Up Unused IAM Policy Versions
# Scenario:    CloudGoat iam_privesc_by_rollback
# Author:      Justin Steele
#
# What this does:
#   - Lists all customer-managed IAM policies
#   - For each policy, deletes all non-default versions
#   - Leaves the active (default) version untouched
#
# Why this matters:
#   - Unused policy versions are an invisible attack surface
#   - Any user with iam:SetDefaultPolicyVersion can activate them
#   - AWS allows up to 5 versions — old ones should be deleted immediately
# =============================================================================

set -euo pipefail

REGION="${1:-us-east-1}"

echo "[*] Scanning for IAM policies with multiple versions..."
echo ""

# Get all customer-managed policies (scope Local = not AWS managed)
POLICY_ARNS=$(aws iam list-policies \
  --scope Local \
  --region "$REGION" \
  --query 'Policies[].Arn' \
  --output text)

if [ -z "$POLICY_ARNS" ]; then
  echo "[!] No customer-managed policies found."
  exit 0
fi

CLEANED=0

for POLICY_ARN in $POLICY_ARNS; do
  # Get all non-default versions
  NON_DEFAULT_VERSIONS=$(aws iam list-policy-versions \
    --policy-arn "$POLICY_ARN" \
    --query 'Versions[?IsDefaultVersion==`false`].VersionId' \
    --output text)

  if [ -z "$NON_DEFAULT_VERSIONS" ]; then
    continue
  fi

  echo "[*] $POLICY_ARN has unused versions: $NON_DEFAULT_VERSIONS"

  for VERSION_ID in $NON_DEFAULT_VERSIONS; do
    echo "    Deleting $VERSION_ID..."
    aws iam delete-policy-version \
      --policy-arn "$POLICY_ARN" \
      --version-id "$VERSION_ID"
    echo "    [+] Deleted $VERSION_ID"
    CLEANED=$((CLEANED + 1))
  done
done

echo ""
echo "============================================="
echo " Done. Deleted $CLEANED unused policy version(s)."
echo "============================================="
echo ""
echo " Next steps:"
echo "   1. Remove iam:SetDefaultPolicyVersion from non-admin users"
echo "   2. Enable CloudWatch alarm on SetDefaultPolicyVersion calls"
echo "   3. Enable IAM Access Analyzer for ongoing monitoring"
echo "============================================="
