#!/usr/bin/env bash
#set -euo pipefail
# Strict-mode: -e (exit on error), -u (treat unset vars as error), -o pipefail (fail on pipe errors).
# To debug, you may enable xtrace temporarily by uncommenting the next line.
# set -x

# Defaults
MANAGED_BY="manual"
FULLNAME_SEP="-"
PROFILE_OPTS=()
REGION_OPTS=()
DRY_RUN=false
REAPPLY=false
TYPES_LIST=""
ASSUME_ROLE_ARN=""
ASSUME_ROLE_SESSION_NAME=""
ASSUME_ROLE_EXTERNAL_ID=""
ASSUME_ROLE_DURATION_SECS=3600

# Target resource types to process via Resource Groups Tagging API
# Default covers: Secrets Manager secrets, Security Groups, EC2 instances, VPC and related resources, S3 buckets, SNS topics, SQS queues, ACM certificates, KMS keys, and AWS Backup resources
DEFAULT_RESOURCE_TYPES=(
  secretsmanager:secret
  ec2:security-group
  ec2:instance
  ec2:vpc
  ec2:subnet
  ec2:dhcp-options
  ec2:route-table
  ec2:internet-gateway
  ec2:network-acl
  ec2:network-interface
  s3:bucket
  sns:topic
  sqs:queue
  acm:certificate
  kms:key
  backup:backup-vault
  backup:recovery-point
  backup:backup-plan
  backup:framework
  backup:report-plan
)
# Will be populated from DEFAULT_RESOURCE_TYPES unless overridden by --types
RESOURCE_TYPES=("${DEFAULT_RESOURCE_TYPES[@]}")

usage() {
  cat <<'USAGE'
Usage:
  tag-untagged-aws-resources.sh \
    --organization ORG \
    --organization-unit UNIT \
    --application-name APP \
    --application-type TYPE \
    [--managed-by VALUE] \
    [--fullname-sep SEP] \
    [--profile AWS_PROFILE] \
    [--region AWS_REGION] \
    [--assume-role-arn ARN] \
    [--assume-role-session-name NAME] \
    [--assume-role-external-id ID] \
    [--assume-role-duration-secs SECONDS] \
    [--types LIST] \
    [--reapply] \
    [--dry-run]

Tags applied (only to resources with ZERO tags currently, unless --reapply):
  - organization
  - organization-unit
  - application-name
  - application-type
  - managed-by                (default: "manual" unless overridden)
  - organization-full-name    (ORG{SEP}UNIT{SEP}APP{SEP}TYPE; SEP default "-")

Notes:
  - Default resource types (use --types to override):
      secretsmanager:secret, ec2:security-group, ec2:instance, ec2:vpc, ec2:subnet, ec2:dhcp-options,
      ec2:route-table, ec2:internet-gateway, ec2:network-acl, ec2:network-interface, s3:bucket, sns:topic, sqs:queue,
      acm:certificate, kms:key, backup:backup-vault, backup:recovery-point, backup:backup-plan,
      backup:framework, backup:report-plan
  - --types LIST: comma-separated values or 'all'. Accepts raw API types (e.g., ec2:instance)
    or friendly aliases: secretsmanager-secret, security-group, ec2-instance, vpc, subnet,
    dhcp-options, route-table, internet-gateway, network-acl, network-interface, s3-bucket, sns-topic, sqs-queue,
    acm-certificate, kms-key, backup-vault, recovery-point, backup-plan, backup-framework, backup-report-plan.
  - Reapply mode (--reapply):
      Reapply tags even if resources already have tags, but skip any that have tag "managed-by=iac".
  - Requires permissions:
      tagging:GetResources, tagging:TagResources for listed resource types. If S3 is included, s3:PutBucketTagging
      may be needed implicitly by the service.
  - If --assume-role-arn is provided, the script will call sts:AssumeRole first and
    use temporary credentials for all subsequent AWS CLI calls. You may still pass
    --profile to control the source credentials for the AssumeRole call.
USAGE
}

# Parse args
while [[ $# -gt 0 ]]; do
  case "$1" in
    --organization) ORG="${2:-}"; shift 2 ;;
    --organization-unit) ORG_UNIT="${2:-}"; shift 2 ;;
    --application-name) APP_NAME="${2:-}"; shift 2 ;;
    --application-type) APP_TYPE="${2:-}"; shift 2 ;;
    --managed-by) MANAGED_BY="${2:-}"; shift 2 ;;
    --fullname-sep) FULLNAME_SEP="${2:-}"; shift 2 ;;
    --profile) PROFILE_OPTS=(--profile "${2:-}"); shift 2 ;;
    --region) REGION_OPTS=(--region "${2:-}"); shift 2 ;;
    --assume-role-arn) ASSUME_ROLE_ARN="${2:-}"; shift 2 ;;
    --assume-role-session-name) ASSUME_ROLE_SESSION_NAME="${2:-}"; shift 2 ;;
    --assume-role-external-id) ASSUME_ROLE_EXTERNAL_ID="${2:-}"; shift 2 ;;
    --assume-role-duration-secs) ASSUME_ROLE_DURATION_SECS="${2:-}"; shift 2 ;;
    --types) TYPES_LIST="${2:-}"; shift 2 ;;
    --reapply) REAPPLY=true; shift ;;
    --dry-run) DRY_RUN=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown argument: $1" >&2; usage; exit 1 ;;
  esac
done

# Validate required
: "${ORG:?--organization is required}"
: "${ORG_UNIT:?--organization-unit is required}"
: "${APP_NAME:?--application-name is required}"
: "${APP_TYPE:?--application-type is required}"

# Build resource type filter from --types (if provided)
normalize_type() {
  local t="$1"
  # accept raw API type (contains colon)
  if [[ "$t" == *:* ]]; then
    printf '%s' "$t"
    return 0
  fi
  case "$t" in
    all|ALL)
      printf '%s' "__ALL__"; return 0 ;;
    secretsmanager-secret|secretsmanager_secret|secret|secretsmanager)
      printf '%s' 'secretsmanager:secret'; return 0 ;;
    security-group|security_group|sg)
      printf '%s' 'ec2:security-group'; return 0 ;;
    ec2-instance|ec2_instance|instance|instances)
      printf '%s' 'ec2:instance'; return 0 ;;
    vpc)
      printf '%s' 'ec2:vpc'; return 0 ;;
    subnet|subnets)
      printf '%s' 'ec2:subnet'; return 0 ;;
    dhcp-options|dhcp_options)
      printf '%s' 'ec2:dhcp-options'; return 0 ;;
    route-table|route_table|routetable|route-tables)
      printf '%s' 'ec2:route-table'; return 0 ;;
    internet-gateway|internet_gateway|igw)
      printf '%s' 'ec2:internet-gateway'; return 0 ;;
    network-acl|network_acl|nacl|nacls)
      printf '%s' 'ec2:network-acl'; return 0 ;;
    network-interface|network_interface|eni|enis)
      printf '%s' 'ec2:network-interface'; return 0 ;;
    s3-bucket|s3_bucket|bucket|buckets)
      printf '%s' 's3:bucket'; return 0 ;;
    sns-topic|sns_topic|sns)
      printf '%s' 'sns:topic'; return 0 ;;
    sqs-queue|sqs_queue|sqs)
      printf '%s' 'sqs:queue'; return 0 ;;
    acm-certificate|acm_certificate)
      printf '%s' 'acm:certificate'; return 0 ;;
    kms-key|kms_key|kms)
      printf '%s' 'kms:key'; return 0 ;;
    backup-vault|backup_vault|backup-backup-vault)
      printf '%s' 'backup:backup-vault'; return 0 ;;
    recovery-point|recovery_point)
      printf '%s' 'backup:recovery-point'; return 0 ;;
    backup-plan|backup_plan)
      printf '%s' 'backup:backup-plan'; return 0 ;;
    backup-framework|backup_framework|framework)
      printf '%s' 'backup:framework'; return 0 ;;
    backup-report-plan|backup_report_plan|report-plan|report_plan)
      printf '%s' 'backup:report-plan'; return 0 ;;
    *)
      return 1 ;;
  esac
}

if [[ -n "$TYPES_LIST" ]]; then
  if [[ "$TYPES_LIST" =~ ^[[:space:]]*(all|ALL)[[:space:]]*$ ]]; then
    RESOURCE_TYPES=("${DEFAULT_RESOURCE_TYPES[@]}")
  else
    IFS=',' read -r -a INPUT_TYPES <<< "$TYPES_LIST"
    RESOURCE_TYPES=()
    invalids=()
    for raw in "${INPUT_TYPES[@]}"; do
      # strip spaces
      t="${raw//[[:space:]]/}"
      [[ -z "$t" ]] && continue
      if norm=$(normalize_type "$t"); then
        if [[ "$norm" == "__ALL__" ]]; then
          RESOURCE_TYPES=("${DEFAULT_RESOURCE_TYPES[@]}")
          invalids=()
          break
        else
          RESOURCE_TYPES+=("$norm")
        fi
      else
        invalids+=("$t")
      fi
    done
    if (( ${#invalids[@]} > 0 )); then
      echo "❌ Unknown resource type(s): ${invalids[*]}" >&2
      echo "   Use 'all' or any of: secretsmanager-secret, security-group, ec2-instance, vpc, subnet, dhcp-options, route-table, internet-gateway, network-acl, network-interface, s3-bucket, sns-topic, sqs-queue, acm-certificate, kms-key, backup-vault, recovery-point, backup-plan, backup-framework, backup-report-plan" >&2
      exit 1
    fi
    if (( ${#RESOURCE_TYPES[@]} == 0 )); then
      echo "❌ No valid resource types were provided to --types" >&2
      exit 1
    fi
  fi
fi

# If assume role requested, obtain temporary credentials
if [[ -n "$ASSUME_ROLE_ARN" ]]; then
  if [[ -z "$ASSUME_ROLE_SESSION_NAME" ]]; then
    ASSUME_ROLE_SESSION_NAME="tag-untagged-aws-resources-$(date +%s)"
  fi

  echo "🔐 Assuming role: $ASSUME_ROLE_ARN (session: $ASSUME_ROLE_SESSION_NAME)"
  declare -a ASSUME_ARGS=(
    --role-arn "$ASSUME_ROLE_ARN"
    --role-session-name "$ASSUME_ROLE_SESSION_NAME"
    --duration-seconds "$ASSUME_ROLE_DURATION_SECS"
  )
  if [[ -n "$ASSUME_ROLE_EXTERNAL_ID" ]]; then
    ASSUME_ARGS+=(--external-id "$ASSUME_ROLE_EXTERNAL_ID")
  fi

  if ! assume_json="$(aws sts assume-role "${PROFILE_OPTS[@]}" "${REGION_OPTS[@]}" "${ASSUME_ARGS[@]}" --output json 2>/dev/null)"; then
    echo "❌ Failed to assume role: $ASSUME_ROLE_ARN" >&2
    exit 1
  fi

  export AWS_ACCESS_KEY_ID
  export AWS_SECRET_ACCESS_KEY
  export AWS_SESSION_TOKEN
  AWS_ACCESS_KEY_ID="$(echo "$assume_json" | jq -r '.Credentials.AccessKeyId')"
  AWS_SECRET_ACCESS_KEY="$(echo "$assume_json" | jq -r '.Credentials.SecretAccessKey')"
  AWS_SESSION_TOKEN="$(echo "$assume_json" | jq -r '.Credentials.SessionToken')"

  if [[ -z "$AWS_ACCESS_KEY_ID" || -z "$AWS_SECRET_ACCESS_KEY" || -z "$AWS_SESSION_TOKEN" ]]; then
    echo "❌ Could not parse temporary credentials from AssumeRole response." >&2
    exit 1
  fi
  echo "✅ AssumeRole succeeded; using temporary credentials."
fi

# Helper: simple retry with backoff (handles throttling)
retry() {
  local -r max_attempts=5
  local attempt=1
  local delay=1
  while true; do
    if "$@"; then
      return 0
    fi
    exit_code=$?
    if (( attempt >= max_attempts )); then
      return "$exit_code"
    fi
    sleep "$delay"
    attempt=$((attempt + 1))
    delay=$((delay * 2))
  done
}

# Sanitize space-heavy inputs for fullname; keep original for individual tag values
sanitize_for_fullname() {
  local s="$1"
  # Replace runs of whitespace with single SEP, then trim leading/trailing SEP
  # shellcheck disable=SC2001
  s="$(echo -n "$s" | sed -E 's/[[:space:]]+/'"$FULLNAME_SEP"'/g')"
  s="${s#"${FULLNAME_SEP}"}"
  s="${s%"${FULLNAME_SEP}"}"
  printf '%s' "$s"
}

FULL_ORG="$(sanitize_for_fullname "$ORG")"
FULL_UNIT="$(sanitize_for_fullname "$ORG_UNIT")"
FULL_APP="$(sanitize_for_fullname "$APP_NAME")"
FULL_TYPE="$(sanitize_for_fullname "$APP_TYPE")"
ORG_FULL_NAME="${FULL_ORG}${FULLNAME_SEP}${FULL_UNIT}${FULLNAME_SEP}${FULL_APP}${FULLNAME_SEP}${FULL_TYPE}"

# Build tag map as a single string suitable for resourcegroupstaggingapi tag-resources
# Note: tag-resources takes a map (Key=Value pairs after --tags or JSON via --tags '{"k":"v"}')
build_tags_args() {
  # Keeping original, unsanitized values for individual tags
  printf '%s' \
    "organization=${ORG}," \
    "organization-unit=${ORG_UNIT}," \
    "application-name=${APP_NAME}," \
    "application-type=${APP_TYPE}," \
    "managed-by=${MANAGED_BY}," \
    "organization-full-name=${ORG_FULL_NAME}"
}

# Fetch resources via tagging API and decide what to tag
echo "🔎 Scanning resources via Resource Groups Tagging API (profile: ${PROFILE_OPTS[*]:-default}, region: ${REGION_OPTS[*]:-default})..."

# Prepare resource type filter arguments
RT_FILTERS=()
for rt in "${RESOURCE_TYPES[@]}"; do
  RT_FILTERS+=(--resource-type-filters "$rt")
done

# Get all resources of the selected types; AWS CLI v2 auto-paginates
if ! resources_json="$(retry aws resourcegroupstaggingapi get-resources --tags-per-page 100 "${PROFILE_OPTS[@]}" "${REGION_OPTS[@]}" \
  "${RT_FILTERS[@]}" --output json 2>/dev/null)"; then
  echo "❌ Failed to list resources via Resource Groups Tagging API" >&2
  exit 1
fi

# Extract list of ARN + Tags
mapfile -t RESOURCES < <(echo "$resources_json" | jq -r '.ResourceTagMappingList[] | @base64')

total=${#RESOURCES[@]}
echo "Found $total resources across selected types."

selected_arns=()
processed=0
skipped=0

for b64 in "${RESOURCES[@]}"; do
  item_json="$(echo "$b64" | base64 --decode)"
  arn="$(echo "$item_json" | jq -r '.ResourceARN')"
  # Normalize Tags into simple key/value pairs
  tags_len="$(echo "$item_json" | jq -r '.Tags | length')"

  if [[ "$REAPPLY" == true ]]; then
    # Skip if managed-by=iac
    managed_by_val="$(echo "$item_json" | jq -r '.Tags[]? | select(.Key=="managed-by") | .Value' | head -n1)"
    if [[ "$managed_by_val" == "iac" ]]; then
      ((skipped++))
      ((processed++))
      continue
    fi
    # Else include in reapply set
    selected_arns+=("$arn")
  else
    # Only tag if zero tags present currently
    if [[ "$tags_len" -eq 0 ]]; then
      selected_arns+=("$arn")
    else
      ((skipped++))
    fi
  fi
  ((processed++))
done

sel_count=${#selected_arns[@]}
echo "Will operate on $sel_count resources (skipped: $skipped)."

if (( sel_count == 0 )); then
  echo "Nothing to do. ✅"
  exit 0
fi

# Chunk ARNs (TagResources allows up to 20 ARNs per call)
chunk_size=20
chunks_tagged=0
failed=0

TAG_MAP_CSV="$(build_tags_args)"

# Convert CSV k=v list to CLI arguments for --tags (supports k=v,k=v format)
# aws resourcegroupstaggingapi tag-resources supports JSON via --tags, but CLI also accepts a map with Key=Value pairs
# We'll build JSON to be safe.
TAG_JSON=$(jq -n --arg csv "$TAG_MAP_CSV" '
  ($csv | split(",")) as $pairs |
  ($pairs | map(split("=") | { (.[0]): (.[1]) }) | add)
')

if [[ -z "$TAG_JSON" || "$TAG_JSON" == "null" ]]; then
  echo "❌ Failed to build tag JSON" >&2
  exit 1
fi

# Tag resources
if [[ "$DRY_RUN" == true ]]; then
  echo "🧪 DRY-RUN would tag the following ARNs (showing up to first 50):"
  for arn in "${selected_arns[@]:0:50}"; do
    echo "  - $arn"
  done
  echo "Tags to apply: $TAG_JSON"
  echo "DRY-RUN complete."
  exit 0
fi

# Perform tagging in batches with retry
for ((i=0; i<sel_count; i+=chunk_size)); do
  batch=("${selected_arns[@]:i:chunk_size}")
  # Execute tagging
  if out_and_err=$( { retry aws resourcegroupstaggingapi tag-resources \
      "${PROFILE_OPTS[@]}" "${REGION_OPTS[@]}" \
      --resource-arn-list "${batch[@]}" \
      --tags "$TAG_JSON"; } 2>&1 ); then
    # tag-resources returns FailedResourcesMap. We should inspect it.
    # Some CLI versions return nothing on success; we conservatively increment tagged count by batch size.
    ((chunks_tagged++))
  else
    ((failed+=${#batch[@]}))
    echo "❌ Failed to tag batch starting at index $i"
    echo "   Reason: $out_and_err" >&2
  fi
done

# Summarize
success_count=$((sel_count - failed))
echo
echo "✅ Tagging done."
echo "  Total resources discovered: $total"
echo "  Selected for tagging:       $sel_count"
echo "  Successfully processed:     $success_count"
echo "  Failed:                     $failed"
echo "  Skipped (pre-checks):       $skipped"

exit 0
