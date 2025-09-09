#!/usr/bin/env bash
set -euo pipefail

# Defaults
MANAGED_BY="manual"
FULLNAME_SEP="-"
PROFILE_OPTS=()
REGION_OPTS=()
INCLUDE_SERVICE_LINKED=false
DRY_RUN=false

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
    [--include-service-linked] \
    [--dry-run]

Tags applied (only to roles with ZERO tags currently):
  - organization
  - organization-unit
  - application-name
  - application-type
  - managed-by                (default: "manual" unless overridden)
  - organization-full-name    (ORG{SEP}UNIT{SEP}APP{SEP}TYPE; SEP default "-")

Notes:
  - Skips AWS service-linked roles (name starting with "AWSServiceRoleFor") by default.
  - Requires IAM permissions: iam:ListRoles, iam:ListRoleTags, iam:TagRole.
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
  if [[ "$INCLUDE_SERVICE_LINKED" == false && "$role_name" == AWSServiceRoleFor* ]]; then
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
    if retry aws iam tag-role "${PROFILE_OPTS[@]}" "${REGION_OPTS[@]}" \
      --role-name "$role_name" \
      --tags "${TAG_ARGS[@]}"; then
      ((tagged++))
      echo "🏷️  Tagged role: $role_name"
    else
      ((skipped++))
      echo "❌ Failed to tag role: $role_name (skipping)"
    fi
  fi

  ((processed++))
done

echo
echo "✅ Done."
echo "  Total roles:        $total"
echo "  Tagged now:         $tagged"
echo "  Already had tags:   $already_tagged"
echo "  Skipped:            $skipped"