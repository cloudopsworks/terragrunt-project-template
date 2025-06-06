#!/bin/bash
set -euo pipefail

UPGRADE=false
REPORT_GHACTION=false
PATH_VALUE=
COMMENT_PR=false
COMMENT_PR_NUM=
# Help function
function show_help() {
  echo "Usage: $0 [options]"
  echo ""
  echo "Options:"
  echo "  -u, --upgrade            Update the terragrunt.hcl files with the latest version"
  echo "  -p, --path <path>       Specify a path to search for terragrunt.hcl files"
  echo "  -c, --comment-pr-num <comment_pr_num> Specify a PR number to comment on"
  echo "  -r, --report-ghaction    Report to GitHub Actions"
  echo "  -h, --help              Show this help message"
}


# Support the following flags:
# -u or --upgrade: Update the terragrunt.hcl files with the latest version
# -p <path> or --path <path>: Specify a path to search for terragrunt.hcl files
# -c <comment_pr_num> or --comment-pr-num <comment_pr_num>: Specify a PR number to comment on
# -r or --report-ghaction: Report to GitHub Actions
# -h or --help: Show help message
while [[ $# -gt 0 ]]; do
  case $1 in
    -u|--upgrade)
      UPGRADE=true
      shift
      ;;
    -p|--path)
      # parses 2 arguments so neede to shift twice
      if [[ -z "${2:-}" ]]; then
        echo "Error: --path requires a non-empty option argument."
        exit 1
      fi
      PATH_VALUE="$2"
      shift
      shift
      ;;
    -c|--comment-pr-num)
      # parses 2 arguments so neede to shift twice
      if [[ -z "${2:-}" ]]; then
        echo "Error: --comment_pr_num requires a non-empty option argument."
        exit 1
      fi
      COMMENT_PR=true
      COMMENT_PR_NUM="$2"
      shift
      shift
      ;;
    -r|--report-ghaction)
      REPORT_GHACTION=true
      shift
      ;;
    -h|--help)
      # print Command Help use a function
      show_help
      exit 0
      ;;
    *)
      # print Command Help
      echo "Unknown option: $1"
      show_help
      exit 1
      ;;
  esac
done

#if PATH_VALUE is not empty CD to that directory
if [[ -n "$PATH_VALUE" ]]; then
  if [[ ! -d "$PATH_VALUE" ]]; then
    echo "Error: $PATH_VALUE is not a directory."
    exit 1
  fi
  cd "$PATH_VALUE" || exit 1
fi

echo "🔍 Searching for terragrunt.hcl files..."
find . -type f -name 'terragrunt.hcl' | grep -v '.terragrunt-cache' | while read -r file; do
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
    latest=$(echo "$tags" | grep -E '^v?[0-9]+\.[0-9]+\.[0-9]+$' | sort -V | tail -n1)
    if [[ -z "$latest" ]]; then
      echo "⚠️  No semantic version tags found for $repo"
      continue
    fi

    if [[ "$ref" != "$latest" ]]; then
      echo "🚨 Module in $file is outdated:"
      echo "    Current: $ref"
      echo "    Latest:  $latest"

      if $REPORT_GHACTION; then
        if [[ -z "$PATH_VALUE" ]]; then
          echo "::warning:: 🚨 Module in $file is outdated: $file | $repo | Current: $ref | Latest: $latest"
        else
          echo "::warning:: 🚨 Module in $PATH_VALUE/$file is outdated: $file | $repo | Current: $ref | Latest: $latest"
        fi
        if $COMMENT_PR; then
          if [[ -z "$PATH_VALUE" ]]; then
            gh pr comment $COMMENT_PR_NUM --body "🚨 Module in $file is outdated: $file | $repo | Current: $ref | Latest: $latest"
          else
            gh pr comment $COMMENT_PR_NUM --body "🚨 Module in $PATH_VALUE/$file is outdated: $file | $repo | Current: $ref | Latest: $latest"
          fi
        fi
      fi

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
