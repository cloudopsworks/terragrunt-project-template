#!/usr/bin/env bash
#set -euo pipefail
# Strict-mode: -e (exit on error), -u (treat unset vars as error), -o pipefail (fail on pipe errors).
# To debug, you may enable xtrace temporarily by uncommenting the next line.
#set -x

# Defaults
MANAGED_BY="manual"
FULLNAME_SEP="-"
PROFILE_OPTS=()
REGION_OPTS=()
INCLUDE_SERVICE_LINKED=false
DRY_RUN=false
ASSUME_ROLE_ARN=""
ASSUME_ROLE_SESSION_NAME=""
ASSUME_ROLE_EXTERNAL_ID=""
ASSUME_ROLE_DURATION_SECS=3600

usage() {
  cat <<'USAGE'
Usage:
  tag-untagged-iam-roles.sh \
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
    [--include-service-linked] \
    [--dry-run]

Tags applied (only to resources with ZERO tags currently):
  - organization
  - organization-unit
  - application-name
  - application-type
  - managed-by                (default: "manual" unless overridden)
  - organization-full-name    (ORG{SEP}UNIT{SEP}APP{SEP}TYPE; SEP default "-")

Notes:
  - Processes both IAM roles and customer-managed IAM policies in one run.
  - Skips AWS service-linked roles (name starting with "AWSServiceRoleFor" or path "/aws-service-role/") by default.
  - Skips roles that are not modifiable (detected when TagRole returns "This role is not modifiable").
  - Requires IAM permissions:
      iam:ListRoles, iam:ListRoleTags, iam:TagRole,
      iam:ListPolicies, iam:ListPolicyTags, iam:TagPolicy
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
    --include-service-linked) INCLUDE_SERVICE_LINKED=true; shift ;;
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

# If assume role requested, obtain temporary credentials
if [[ -n "$ASSUME_ROLE_ARN" ]]; then
  # default session name if not provided
  if [[ -z "$ASSUME_ROLE_SESSION_NAME" ]]; then
    ASSUME_ROLE_SESSION_NAME="tag-untagged-iam-roles-$(date +%s)"
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

  # Attempt assume-role using the provided profile/region as source credentials
  if ! assume_json="$(aws sts assume-role "${PROFILE_OPTS[@]}" "${REGION_OPTS[@]}" "${ASSUME_ARGS[@]}" --output json 2>/dev/null)"; then
    echo "❌ Failed to assume role: $ASSUME_ROLE_ARN" >&2
    exit 1
  fi

  # Export temporary credentials for the remainder of the script
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
  # Replace runs of whitespace with single SEP, trim leading/trailing SEP
  local s="$1"
  # shellcheck disable=SC2001
  s="$(echo -n "$s" | sed -E 's/[[:space:]]+/'"$FULLNAME_SEP"'/g')"
  # Trim leading/trailing separators
  s="${s#"${FULLNAME_SEP}"}"
  s="${s%"${FULLNAME_SEP}"}"
  printf '%s' "$s"
}

FULL_ORG="$(sanitize_for_fullname "$ORG")"
FULL_UNIT="$(sanitize_for_fullname "$ORG_UNIT")"
FULL_APP="$(sanitize_for_fullname "$APP_NAME")"
FULL_TYPE="$(sanitize_for_fullname "$APP_TYPE")"
ORG_FULL_NAME="${FULL_ORG}${FULLNAME_SEP}${FULL_UNIT}${FULLNAME_SEP}${FULL_APP}${FULLNAME_SEP}${FULL_TYPE}"

echo "🔎 Scanning IAM roles (profile: ${PROFILE_OPTS[*]:-default}, region: ${REGION_OPTS[*]:-default})..."
# AWS CLI v2 auto-paginates; collect RoleName and Path for filtering and clarity.
mapfile -t ROLES < <(aws iam list-roles "${PROFILE_OPTS[@]}" "${REGION_OPTS[@]}" \
  --query 'Roles[].{Name:RoleName,Path:Path}' --output json | jq -r '.[] | "\(.Name)\t\(.Path)"')

total=${#ROLES[@]}
echo "Found $total roles."

processed=0
tagged=0
skipped=0
already_tagged=0

for line in "${ROLES[@]}"; do
  role_name="${line%%$'\t'*}"
  role_path="${line#*$'\t'}"

  # Skip service-linked roles unless user opted in
  if [[ "$INCLUDE_SERVICE_LINKED" == false && ( "$role_name" == AWSServiceRoleFor* || "$role_path" == /aws-service-role/* ) ]]; then
    ((skipped++))
    echo "⏭️  Skip service-linked role: $role_name"
    continue
  fi

  # Check current tags
  # If role was deleted mid-run, ignore failures
  if ! tags_json="$(retry aws iam list-role-tags "${PROFILE_OPTS[@]}" "${REGION_OPTS[@]}" --role-name "$role_name" --output json 2>/dev/null)"; then
    ((skipped++))
    echo "⚠️  Could not list tags for role: $role_name (skipping)"
    continue
  fi

  current_count="$(echo "$tags_json" | jq '.Tags | length')"
  if [[ "$current_count" -gt 0 ]]; then
    ((already_tagged++))
    echo "✔️  Already has tags ($current_count): $role_name"
    continue
  fi

  # Build tag arguments
  # Note: keep original (unsanitized) values for individual tags.
  declare -a TAG_ARGS=(
    "Key=organization,Value=${ORG}"
    "Key=organization-unit,Value=${ORG_UNIT}"
    "Key=application-name,Value=${APP_NAME}"
    "Key=application-type,Value=${APP_TYPE}"
    "Key=managed-by,Value=${MANAGED_BY}"
    "Key=organization-full-name,Value=${ORG_FULL_NAME}"
  )

  if [[ "$DRY_RUN" == true ]]; then
    echo "🧪 DRY-RUN would tag role: $role_name"
    printf '      %s\n' "${TAG_ARGS[@]}"
  else
    # Attempt tagging; if the role is not modifiable, skip gracefully.
    tag_err=""
    if out_and_err=$( { retry aws iam tag-role "${PROFILE_OPTS[@]}" "${REGION_OPTS[@]}" \
      --role-name "$role_name" \
      --tags "${TAG_ARGS[@]}"; } 2>&1 ); then
      ((tagged++))
      echo "🏷️  Tagged role: $role_name"
    else
      tag_err="$out_and_err"
      if [[ "$tag_err" == *"is not modifiable"* || "$tag_err" == *"This role is not modifiable"* ]]; then
        ((skipped++))
        echo "⏭️  Role not modifiable, skipping: $role_name"
      else
        ((skipped++))
        echo "❌ Failed to tag role: $role_name (skipping)"
        echo "   Reason: $tag_err" >&2
      fi
    fi
  fi

  ((processed++))
done

echo
echo "✅ Roles done."
echo "  Total roles:        $total"
echo "  Tagged now:         $tagged"
echo "  Already had tags:   $already_tagged"
echo "  Skipped:            $skipped"

# -----------------------------
# Process customer-managed IAM policies
# -----------------------------

echo
echo "🔎 Scanning IAM customer-managed policies (profile: ${PROFILE_OPTS[*]:-default}, region: ${REGION_OPTS[*]:-default})..."
# Collect PolicyName and Arn for each customer-managed policy
mapfile -t POLICIES < <(aws iam list-policies "${PROFILE_OPTS[@]}" "${REGION_OPTS[@]}" \
  --scope Local \
  --query 'Policies[].{Arn:Arn,Name:PolicyName}' --output json | jq -r '.[] | "\(.Name)\t\(.Arn)"')

p_total=${#POLICIES[@]}
echo "Found $p_total customer-managed policies."

p_processed=0
p_tagged=0
p_skipped=0
p_already_tagged=0

for line in "${POLICIES[@]}"; do
  policy_name="${line%%$'\t'*}"
  policy_arn="${line#*$'\t'}"

  # Check current tags; if policy was deleted mid-run, ignore failures
  if ! p_tags_json="$(retry aws iam list-policy-tags "${PROFILE_OPTS[@]}" "${REGION_OPTS[@]}" --policy-arn "$policy_arn" --output json 2>/dev/null)"; then
    ((p_skipped++))
    echo "⚠️  Could not list tags for policy: $policy_name (skipping)"
    continue
  fi

  p_current_count="$(echo "$p_tags_json" | jq '.Tags | length')"
  if [[ "$p_current_count" -gt 0 ]]; then
    ((p_already_tagged++))
    echo "✔️  Already has tags ($p_current_count): $policy_name"
    continue
  fi

  # Build tag arguments for policies (same as roles)
  declare -a P_TAG_ARGS=(
    "Key=organization,Value=${ORG}"
    "Key=organization-unit,Value=${ORG_UNIT}"
    "Key=application-name,Value=${APP_NAME}"
    "Key=application-type,Value=${APP_TYPE}"
    "Key=managed-by,Value=${MANAGED_BY}"
    "Key=organization-full-name,Value=${ORG_FULL_NAME}"
  )

  if [[ "$DRY_RUN" == true ]]; then
    echo "🧪 DRY-RUN would tag policy: $policy_name"
    printf '      %s\n' "${P_TAG_ARGS[@]}"
  else
    p_tag_err=""
    if out_and_err=$( { retry aws iam tag-policy "${PROFILE_OPTS[@]}" "${REGION_OPTS[@]}" \
      --policy-arn "$policy_arn" \
      --tags "${P_TAG_ARGS[@]}"; } 2>&1 ); then
      ((p_tagged++))
      echo "🏷️  Tagged policy: $policy_name"
    else
      p_tag_err="$out_and_err"
      ((p_skipped++))
      echo "❌ Failed to tag policy: $policy_name (skipping)"
      echo "   Reason: $p_tag_err" >&2
    fi
  fi

  ((p_processed++))
done

echo
echo "✅ Policies done."
echo "  Total policies:     $p_total"
echo "  Tagged now:         $p_tagged"
echo "  Already had tags:   $p_already_tagged"
echo "  Skipped:            $p_skipped"

echo
echo "🎯 Completed tagging roles and policies."
