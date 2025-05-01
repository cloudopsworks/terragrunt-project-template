#!/bin/bash
set -euo pipefail

UPGRADE=false

# Detect --upgrade flag
if [[ "${1:-}" == "--upgrade" ]]; then
  UPGRADE=true
fi

echo "🔍 Searching for terragrunt.hcl files..."
find . -type f -name 'terragrunt.hcl' | while read -r file; do
  echo ""
  echo "📄 Processing: $file"

  # Extract raw source line
  source_line=$(grep -E '^\s*source\s*=' "$file" || true)
  if [[ -z "$source_line" ]]; then
    echo "⚠️  No source found in $file"
    continue
  fi

  # Strip 'source =' and outer quotes (escaped properly)
  source_url=$(echo "$source_line" | sed -E 's/^ *source *= *\"([^\"]+)\"/\1/')

  # Match pattern: supports ?ref= and //?ref=
  if [[ "$source_url" =~ git::https://github.com/([^/]+/[^/.]+)(\.git)?(//[^?]*)?\?ref=([^\"]+) ]]; then
    repo="${BASH_REMATCH[1]}"
    ref="${BASH_REMATCH[4]}"
    echo "🔗 GitHub Repo: $repo"
    echo "📌 Current Ref: $ref"

    # Get tags via GitHub CLI (uses GH_TOKEN)
    tags=$(gh api "repos/${repo}/tags" --jq '.[].name' || echo "")
    if [[ -z "$tags" ]]; then
      echo "❌ Failed to fetch tags for $repo"
      continue
    fi

    # Extract highest semver-style tag
    latest=$(echo "$tags" | grep -E '^v?[0-9]+(\.[0-9]+)*$' | sort -V | tail -n1)
    if [[ -z "$latest" ]]; then
      echo "⚠️  No semantic version tags found for $repo"
      continue
    fi

    if [[ "$ref" != "$latest" ]]; then
      echo "🚨 Module in $file is outdated:"
      echo "    Current: $ref"
      echo "    Latest:  $latest"

      if $UPGRADE; then
        echo "✏️  Updating $file with new ref: $latest"
        # Detect platform for sed in-place option
        if [[ "$OSTYPE" == "darwin"* ]]; then
          sed -i '' -E "s|(^ *source *= *\".*\?ref=)$ref(\")|\1$latest\2|"  $file
        else
          sed -i -E "s|(^ *source *= *\".*\?ref=)$ref(\")|\1$latest\2|"  $file
        fi
      fi
    else
      echo "✅ Module in $file is up to date."
    fi
  else
    echo "⚠️  Could not parse GitHub ref from source URL in $file"
    echo "    Found: $source_url"
  fi
done
