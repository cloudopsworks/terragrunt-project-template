# Agent Guidelines — Terragrunt Project Template

This document provides agentic guidelines for working with repositories created from or derived from the **cloudopsworks/terragrunt-project-template**. It covers two distinct operating contexts.

---

## Environment Detection

Before starting any task, detect the available tooling to choose the most efficient execution path.

### MCP Servers

Check whether any MCP (Model Context Protocol) servers are available in the current session. MCP servers may expose tools for GitHub, Jira, git operations, or IDE integration that can replace manual CLI steps.

- If a **GitHub MCP** is available (e.g., tools named `github_*`, `create_pull_request`, `mcp__github__*`): use it to create pull requests, list branches, fetch repository metadata, and manage issues — do not fall back to `gh` CLI unless the MCP call fails.
- If a **Jira MCP** is available: use it to link PRs to tickets and update issue status instead of relying on the `inputs-jira.yaml` workflow trigger alone.
- If any other MCP server is available, inspect its exposed tools and prefer them over equivalent shell commands where they reduce ambiguity or improve reliability.

### IDE Integration

Check whether the agent is running inside an IDE with active integrations (e.g., JetBrains, VS Code, Cursor):

- If **IDE MCP tools** are available (e.g., `mcp__webstorm__*`, `mcp__vscode__*`): use them for file operations, terminal commands, and project navigation in preference to raw shell calls.
- If an IDE terminal tool is available, prefer it over the generic Bash tool for running `make` targets, as it inherits the project's environment automatically.
- If IDE Git tools are available, use them to stage, diff, and commit files.

### Fallback

If no MCP servers or IDE integrations are detected, use standard CLI tools: `gh` for GitHub operations, `git` for version control, `make` for build targets.

---

## 1. Handling a Freshly Created Repository from This Template

### What this repository is

This is a **Terragrunt/Terraform IaC project template** for managing multi-cloud infrastructure (AWS, Azure, GCP). When a new repository is created from this template, it must be initialized via a boilerplate tool before any infrastructure code is authored.

### Prerequisites

Ensure the following tools are available before proceeding:
- `make`
- `terragrunt` (v0.99+)
- `boilerplate` — installed automatically via `make init/project` if missing
- `gitversion` — required only for version tagging

### Initialization Steps

#### Step 1: Run `make init/project`

This is the **mandatory first step** for any fresh repository. It invokes the boilerplate engine against `.cloudopsworks/boilerplate/main/` and scaffolds the project configuration.

```sh
make init/project
```

You will be prompted for the following variables (or supply them via `--var` flags / `.inputs` file):

| Variable | Description | Options / Default |
|---|---|---|
| `target_cloud` | Cloud provider | `aws` (default), `azure`, `gcp` |
| `state_type` | Terraform state backend | `s3` (default), `gcs`, `azurerm` |
| `mongodb` | Enable MongoDB Atlas support | `false` (default) |
| `maintainer_id` | GitHub username of maintainer | — |
| `maintainer_email` | Maintainer email address | — |
| `zone_ownership_by` | Ownership label | `owned` (default) |
| `zone_managed_by` | Management label | `owned` (default) |
| `iac_project` | Project name (defaults to repo dir name) | auto-detected |
| `runner_set_enabled` | Use custom GitHub runner sets | `false` (default) |
| `runner_set_name` | Runner set name (if enabled) | — |

#### Step 2: Review generated files

After `make init/project` completes, the following files are created or updated:

- `root.hcl` — Terragrunt root configuration (provider, state backend, assume-role)
- `global-inputs.yaml` — Global variable inputs for all modules
- `global-tags.json` — Shared resource tags
- `.cloudopsworks/cloudopsworks-ci.yaml` — CI/CD and repository governance config
- `.cloudopsworks/inputs-jira.yaml` — Jira integration config (optional)
- `.inputs` — Stored boilerplate inputs (cloud/state vars)
- `.inputs_mod` — Stored boilerplate inputs (module-specific vars)
- `.cloudopsworks/.inputs_cicd` — Stored CI/CD boilerplate inputs

#### Step 3: Configure `cloudopsworks-ci.yaml`

Edit `.cloudopsworks/cloudopsworks-ci.yaml` to match the project's governance requirements:

```yaml
config:
  branchProtection: true
  gitFlow:
    enabled: false
    supportBranches: false
  protectedSources:
    - "*.tf"
    - "*.tfvars"
    - OWNERS
    - Makefile
    - .github
  requiredReviewers: 1
  reviewers:
    - <github-username>
  owners:
    - <github-org/team>
  contributors:
    admin:
      - <github-org/team>
    triage: []
    pull: []
    push:
      - <github-org/team>
    maintain: []

cd:
  automatic: false
  deployments:
    master:
      env: production
```

This project uses **GitHub Flow**: `master` is always the deployable branch. All changes flow through short-lived feature or fix branches that merge directly into `master` via pull request.

Adjust `reviewers`, `owners`, and `requiredReviewers` as needed.

#### Step 4: Add infrastructure modules

Structure project-specific infrastructure under purpose-named directories (not inside `sample/`, which is for reference only). Typical layout:

```
common/                   # Shared org-level resources (IAM, etc.)
networking/               # Landing zones, VPCs, Transit Gateways
environments/
  dev/
  test/
  uat/
  production/
```

Each leaf module directory should contain:
- `terragrunt.hcl` — module invocation with `source` and `inputs`
- `inputs.yaml` (optional) — environment-specific variable overrides

#### Step 5: Validate

```sh
make lint    # Validates all HCL files; checks module version references
make clean   # Removes .terragrunt-cache and plan artifacts before committing
```

#### Step 6: Initial commit workflow

1. Create a feature branch for the initial setup:
   ```sh
   make gitflow/feature/start-no-develop:initial-project-setup
   ```
2. Commit all generated and authored files on that branch.
3. Publish the branch to the remote (sets upstream tracking):
   ```sh
   make gitflow/feature/publish
   ```
4. Open a PR targeting `master`:
   ```sh
   make gitflow/feature/finish-no-develop
   ```
5. The CI plan workflow will run automatically on the PR.
6. After approval and merge, the CD workflow can deploy to target environments.

---

## 2. Operations on an Existing Repository Upgraded from Old Versions

### What "upgrade" means

When the upstream template (`cloudopsworks/terragrunt-project-template`) releases a new version, downstream repositories sync changes from it. This typically involves:
- Updated boilerplate templates (new HCL partials, updated root configs)
- New or changed CI/CD workflow files
- Version bumps in `.cloudopsworks/_VERSION`

### Hard Rule: Protected Files — Never Modify

The following files and directories are **owned by the upstream template** and must never be modified by agents operating on downstream repositories. They are overwritten on each upgrade and any local edits will be lost or cause conflicts.

```
.cloudopsworks/boilerplate/      ← entire directory, all subdirectories
.cloudopsworks/hooks/            ← entire directory (module_versions.sh, parse_outputs.sh)
.cloudopsworks/_VERSION          ← template version marker
.cloudopsworks/LICENSE           ← Apache v2.0 license, do not alter
.cloudopsworks/labeler.yml       ← GitHub PR auto-labeling rules
.github/                         ← entire directory (all workflow files, configs)
```

Do not read these files with the intent to modify them. Do not suggest or apply edits to them. If a workflow or hook behavior needs to change, raise it as an upstream issue.

### Allowed Modification Targets

Agents may freely read and modify the following:

| File / Path | Purpose |
|---|---|
| `global-tags.json` | Shared resource tag defaults |
| `.cloudopsworks/cloudopsworks-ci.yaml` | CI/CD governance (reviewers, environments) |
| `.cloudopsworks/inputs-jira.yaml` | Jira integration settings |
| `common/**` | Shared org-level infrastructure modules |
| `environments/**` | Environment-specific infrastructure modules |
| `networking/**` | Networking infrastructure modules |
| Any project-specific directory | Infrastructure authored for this project |

The following files are **boilerplate-generated** and must never be modified directly. They are regenerated by `make init/project` from stored inputs and any manual edits will be overwritten:

```
root.hcl
global-inputs.yaml
.inputs
.inputs_mod
.cloudopsworks/.inputs_cicd
```

### Upgrade Procedure

#### Step 1: Run the appropriate upgrade command

Use the correct upgrade target depending on the version change:

```sh
make repos/upgrade        # Minor upgrade (patch and minor version bumps)
make repos/upgrade/major  # Major upgrade (breaking changes, new major version)
```

These commands pull changes from the upstream template. Protected files will be updated automatically — do not interfere with those changes.

#### Step 2: Re-run `make init/project`

After the upgrade, re-apply the boilerplate to regenerate `root.hcl`, `global-inputs.yaml`, and other templated files using the existing stored inputs:

```sh
make init/project
```

The Makefile automatically picks up `.inputs`, `.inputs_mod`, `.cloudopsworks/.inputs_cicd`, and `.inputs_state` if they exist, so no re-prompting occurs.

#### Step 3: Review generated diffs

Carefully diff the regenerated files against previous versions. The boilerplate may:
- Add new required blocks to `root.hcl`
- Add new keys to `global-inputs.yaml`
- Update provider version constraints

Merge any project-specific customizations that were present in the old versions of these files back into the newly generated ones. After merging customizations, re-format any changed HCL files:

```sh
terragrunt hcl format --working-dir . --exclude-dir .cloudopsworks
```

#### Step 4: Validate

```sh
make lint    # Catches HCL syntax errors and stale module version refs
make clean   # Clears caches and plan artifacts
```

#### Step 5: Commit only non-protected files

Stage and commit only files outside the protected paths. Do not commit changes to `.github/`, `.cloudopsworks/boilerplate/`, `.cloudopsworks/hooks/`, `.cloudopsworks/_VERSION`, `.cloudopsworks/LICENSE`, or `.cloudopsworks/labeler.yml` unless they arrived directly from the upstream merge and are unmodified.

After opening the PR, wait for all CI checks to pass before merging:

```sh
gh pr checks <PR_NUMBER> --watch
```

### Branch and Pull Request Procedure

There is a skill related to this template module and their implementations, it can be found in the [Claude Code Skills - cw-release](https://github.com/cloudopsworks/claude-code-skills/tree/main/cw-release) can be used in any agent anyway, install and use it.

#### General Rules

- **Never push directly to `master`**. All changes must flow through feature or hotfix branches merged via pull request.
- Branches must be created before any change is committed.
- Follow [Semantic Versioning](https://semver.org/) (`MAJOR.MINOR.PATCH`) for all project version tags — GitVersion derives these automatically from commit message annotations.
- GitHub Flow is the branching model: all branches are created from `master` and merged back into `master`. There is no `develop` branch in this project.
- Always use `make gitflow/*` targets for branch operations — never raw `git checkout -b` or `git push -u origin`. These targets handle dependency checks, naming conventions, and upstream tracking automatically.
- Plan consistently and thoroughly before starting any work.
- Use `gh` CLI for PR management. When waiting for CI checks to pass, use `gh pr checks <PR_NUMBER> --watch`.

#### Branch naming and creation

All changes must be made on a dedicated branch, never directly on `master`. Use the `make gitflow/*` targets — never raw `git checkout -b`.

| Branch type | Creation command | When to use | Semver impact |
|---|---|---|---|
| `feature/<name>` | `make gitflow/feature/start-no-develop:<name>` | New infra modules, provider upgrades, new environments | MINOR or MAJOR |
| `hotfix/<version>` | `make gitflow/hotfix/start` (auto-named by GitVersion) | Config corrections, module `?ref=` bumps, CI repairs, doc fixes | PATCH |

> `make gitflow/hotfix/start` automatically computes the branch name as `hotfix/<next-patch-version>` using GitVersion — do not choose the name manually.

#### Publishing branches

After committing changes locally, publish the branch to establish upstream tracking. Never use `git push -u origin` directly.

| Branch type | Publish command |
|---|---|
| `feature/` | `make gitflow/feature/publish` |
| `hotfix/` | `make gitflow/hotfix/publish` |

#### Opening a pull request via finish targets

Use the finish targets to create PRs. These targets verify the branch is in sync with remote before creating the PR — always publish first.

| Branch type | PR creation command |
|---|---|
| `feature/` | `make gitflow/feature/finish-no-develop` |
| `hotfix/` | `make gitflow/hotfix/finish` |

#### PR body format

Use the following format for the PR body. The `+semver:` annotation in the body is required — GitVersion reads it from the merge commit message to determine the next version.

```markdown
## Summary
<One or two sentences describing what this PR does and why.>

## Changes
- <Main change 1>
- <Main change 2>
- <Main change 3>

+semver: <major|minor|patch|fix>

## Checklist
- [ ] HCL formatted (`terragrunt hcl format --working-dir <path> --exclude-dir .cloudopsworks`)
- [ ] `make lint` passes with no errors
- [ ] `make clean` run before committing (no cache artifacts staged)
- [ ] `+semver:` annotation included in PR body matching expected version impact
- [ ] No protected files modified (`.cloudopsworks/boilerplate/`, `.cloudopsworks/hooks/`, `.cloudopsworks/_VERSION`, `.cloudopsworks/LICENSE`, `.cloudopsworks/labeler.yml`, `.github/`)
- [ ] No boilerplate-generated files modified directly (`root.hcl`, `global-inputs.yaml`, `.inputs`, `.inputs_mod`, `.cloudopsworks/.inputs_cicd`)
- [ ] Changes reviewed for correctness in the target environment(s)
- [ ] CI plan output reviewed before merging
```

The CI plan workflow will run automatically against the PR. Do not merge until the plan output has been reviewed and approved by the required reviewers defined in `.cloudopsworks/cloudopsworks-ci.yaml`.

### Module Version Checks

The `.cloudopsworks/hooks/module_versions.sh` hook runs automatically in CI to detect outdated `?ref=` version pins in `terragrunt.hcl` files. When modules are flagged as outdated:

1. Start a hotfix branch:
   ```sh
   make gitflow/hotfix/start
   ```
2. Open the relevant `terragrunt.hcl` file and update the `source` URL's `?ref=` value to the recommended version shown in the CI warning.
3. Format the changed file:
   ```sh
   terragrunt hcl format --working-dir <directory-containing-the-terragrunt.hcl>
   ```
4. Commit with a patch annotation:
   ```sh
   git add <file>
   git commit -m "chore: bump <module> ref to <version> +semver: patch"
   ```
5. Publish and open the PR:
   ```sh
   make gitflow/hotfix/publish
   make gitflow/hotfix/finish
   ```
6. Do not modify the hook script itself.

### CI/CD Governance Updates

When CI/CD settings need to change (new environments, reviewer changes, runner configuration):

1. Edit `.cloudopsworks/cloudopsworks-ci.yaml` only.
2. Do not edit `.github/workflows/` files directly.
3. Commit the change and let the repository governance automation pick it up.

---

## 3. Versioning and Release Management

### Semver Commit Annotations

The project uses GitVersion with commit message parsing. Include a `+semver:` annotation in every commit message and in the PR description body — GitVersion reads it from the merge commit to determine the next version tag.

| Change type | Annotation |
|---|---|
| Breaking / incompatible change | `+semver: major` |
| New feature or minor upgrade | `+semver: minor` or `+semver: feature` or `+semver: breaking` |
| Fix, patch, or hotfix | `+semver: fix` or `+semver: patch` or `+semver: hotfix` |
| Skip version bump | `+semver: none` or `+semver: skip` |

Example commit messages:
```
feat: add spoke VPC module for dev environment +semver: minor
fix: correct assume-role ARN in root.hcl +semver: fix
chore: bump vpc module ?ref= to v3.2.1 +semver: patch
refactor!: replace s3 backend with azurerm +semver: major
```

### Change Type Summary Table

| Change type | Branch type | Semver impact | Annotation |
|---|---|---|---|
| New infrastructure module | `feature/` | MINOR | `+semver: feature` |
| New environment or account | `feature/` | MINOR | `+semver: minor` |
| Provider version upgrade (breaking) | `feature/` | MAJOR | `+semver: breaking` |
| Provider version upgrade (compatible) | `feature/` | MINOR | `+semver: minor` |
| Bug fix / broken configuration | `hotfix/` | PATCH | `+semver: fix` |
| Module `?ref=` version pin update | `hotfix/` | PATCH | `+semver: patch` |
| CI/CD governance update (`cloudopsworks-ci.yaml`) | `hotfix/` | PATCH | `+semver: patch` |
| Template upgrade follow-up (`make repos/upgrade`) | `hotfix/` | PATCH | `+semver: patch` |
| HCL formatting correction only | `hotfix/` | PATCH | `+semver: patch` |

### Feature Branch Workflow (MINOR / MAJOR changes)

```sh
# 1. Start branch from master
make gitflow/feature/start-no-develop:<feature-name>

# 2. Implement changes, then format any changed HCL files
#    Scoped to a specific module directory:
terragrunt hcl format --working-dir <path/to/module>
#    Or from the project root (all files, excluding .cloudopsworks):
terragrunt hcl format --working-dir . --exclude-dir .cloudopsworks

# 3. Validate
make lint

# 4. Commit with semver annotation
git add <specific files>
git commit -m "feat: <description> +semver: minor"

# 5. Publish branch (sets upstream tracking)
make gitflow/feature/publish

# 6. Open PR against master
make gitflow/feature/finish-no-develop

# 7. Wait for CI checks
gh pr checks <PR_NUMBER> --watch
```

### Hotfix Branch Workflow (PATCH changes)

```sh
# 1. Start hotfix branch (auto-named hotfix/<next-patch-version> by GitVersion)
make gitflow/hotfix/start

# 2. Apply fix, then format if HCL was changed
#    Scoped to the changed directory:
terragrunt hcl format --working-dir <path/to/changed/module>
#    Or from the project root:
terragrunt hcl format --working-dir . --exclude-dir .cloudopsworks

# 3. Validate
make lint

# 4. Commit with semver annotation
git add <specific files>
git commit -m "fix: <description> +semver: patch"

# 5. Publish branch (sets upstream tracking)
make gitflow/hotfix/publish

# 6. Open PR against master
make gitflow/hotfix/finish

# 7. Wait for CI checks
gh pr checks <PR_NUMBER> --watch
```

### PR Merge Guidelines

After all CI checks pass and reviewers have approved, merge using `gh pr merge` with a proper merge commit:

```sh
gh pr merge <PR_NUMBER> --repo <owner/repo> --merge \
  --subject "chore: merge <branch> - <short description> +semver: <level>" \
  --body "$(cat <<'EOF'
## Summary

- Bullet point summary of changes

+semver: <level>
EOF
)"
```

Key rules:
- Always use `--merge` (never `--squash` or `--rebase`) — GitVersion requires the full merge commit history to read semver annotations correctly.
- Include `+semver: <level>` in the **body**, not just the subject line.
- After merge, update your local master: `git checkout master && git pull origin master`.
