#!/bin/bash
# =============================================================================
# Detection: IAM Policy Version Rollback (Privilege Escalation)
# Scenario:  CloudGoat iam_privesc_by_rollback
# Author:    Justin Steele
#
# What this detects:
#   - Any call to SetDefaultPolicyVersion (the core of this attack)
#   - IAM enumeration activity (list-policy-versions, get-policy-version)
#
# Requirements:
#   - CloudTrail enabled (management events — on by default)
#   - CloudWatch Log Group receiving CloudTrail logs
# =============================================================================

set -euo pipefail

LOG_GROUP="/aws/cloudtrail/logs"        # Update to your CloudTrail log group
ALARM_EMAIL="security@yourcompany.com"  # Update to your security team email
REGION="us-east-1"
SNS_TOPIC_NAME="security-alerts"

echo "[*] Creating SNS topic..."
SNS_TOPIC_ARN=$(aws sns create-topic \
  --name "$SNS_TOPIC_NAME" \
  --region "$REGION" \
  --query 'TopicArn' \
  --output text)

aws sns subscribe \
  --topic-arn "$SNS_TOPIC_ARN" \
  --protocol email \
  --notification-endpoint "$ALARM_EMAIL" \
  --region "$REGION"

echo "[+] SNS topic: $SNS_TOPIC_ARN"

# ── Detection 1: SetDefaultPolicyVersion ─────────────────────────────────────
echo "[*] Creating alarm: SetDefaultPolicyVersion..."

aws logs put-metric-filter \
  --log-group-name "$LOG_GROUP" \
  --filter-name "IAMPolicyVersionRollback" \
  --filter-pattern '{ $.eventName = "SetDefaultPolicyVersion" }' \
  --metric-transformations \
    metricName=PolicyVersionRollback,metricNamespace=SecurityDetections,metricValue=1,defaultValue=0 \
  --region "$REGION"

aws cloudwatch put-metric-alarm \
  --alarm-name "ALERT-IAMPolicyVersionRollback" \
  --alarm-description "SetDefaultPolicyVersion called — possible IAM privilege escalation via policy rollback" \
  --metric-name "PolicyVersionRollback" \
  --namespace "SecurityDetections" \
  --statistic Sum \
  --period 300 \
  --threshold 1 \
  --comparison-operator GreaterThanOrEqualToThreshold \
  --evaluation-periods 1 \
  --alarm-actions "$SNS_TOPIC_ARN" \
  --treat-missing-data notBreaching \
  --region "$REGION"

echo "[+] Alarm created: ALERT-IAMPolicyVersionRollback"

# ── Detection 2: IAM Enumeration Spike ───────────────────────────────────────
echo "[*] Creating alarm: IAM enumeration activity..."

aws logs put-metric-filter \
  --log-group-name "$LOG_GROUP" \
  --filter-name "IAMEnumerationActivity" \
  --filter-pattern '{ ($.eventName = "ListPolicyVersions") || ($.eventName = "GetPolicyVersion") || ($.eventName = "ListAttachedUserPolicies") }' \
  --metric-transformations \
    metricName=IAMEnumeration,metricNamespace=SecurityDetections,metricValue=1,defaultValue=0 \
  --region "$REGION"

aws cloudwatch put-metric-alarm \
  --alarm-name "ALERT-IAMEnumerationSpike" \
  --alarm-description "High volume IAM enumeration calls — possible privilege escalation reconnaissance" \
  --metric-name "IAMEnumeration" \
  --namespace "SecurityDetections" \
  --statistic Sum \
  --period 300 \
  --threshold 10 \
  --comparison-operator GreaterThanOrEqualToThreshold \
  --evaluation-periods 1 \
  --alarm-actions "$SNS_TOPIC_ARN" \
  --treat-missing-data notBreaching \
  --region "$REGION"

echo "[+] Alarm created: ALERT-IAMEnumerationSpike"
echo ""
echo "============================================="
echo " Detection setup complete"
echo " Alarms: ALERT-IAMPolicyVersionRollback"
echo "         ALERT-IAMEnumerationSpike"
echo "============================================="
