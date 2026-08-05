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
- If an IDE terminal tool is available, prefer it over the generic Bash tool for running `tronador` commands, as it inherits the project's environment automatically.
- If IDE Git tools are available, use them to stage, diff, and commit files.

### Fallback

If no MCP servers or IDE integrations are detected, use standard CLI tools: `tronador` for project and repository lifecycle operations, `gh` for GitHub operations, and `git` for version control. Fall back to `make` only for the operations listed under [Operations still driven by `make`](#operations-still-driven-by-make).

---

## Tooling: the `tronador` CLI replaces `make`

> **The `Makefile` is deprecated.** All project and repository lifecycle operations must be driven through the `tronador` CLI. The `Makefile` and the network-fetched `.tronador` accelerator include are retained only for backwards compatibility and for the few operations that have no CLI equivalent yet. Do not add new `make` targets, and never use a `make` target when a `tronador` command exists.

### Why

The `make` targets set `TRONADOR_AUTO_INIT := true`, which curls `https://cowk.io/acc` into `.tronador` and clones the accelerator repository on every invocation — a network dependency on every build. The `tronador` CLI is a single installed binary: it never dispatches through a `Makefile`, needs no network fetch to bootstrap itself, provisions the tools it declares, and supports `--dry-run` on every command.

### Command mapping

| Deprecated `make` target | Use instead | Notes |
|---|---|---|
| `make init/project` | `tronador project init` | Picks up `.inputs`, `.inputs_mod`, `.inputs_state`, and `.cloudopsworks/.inputs_cicd` automatically when present, then formats the rendered HCL |
| `make lint` | `tronador project lint` | Alias `tronador project validate`. Read-only |
| `make clean` | `tronador project clean --yes` | Destructive; `--yes` is required non-interactively |
| `make clean/project` | `tronador project clean-inputs --yes` | Destructive; removes the stored boilerplate input files |
| `terragrunt hcl format …` | `tronador project format` | Alias `tronador project fmt` |
| `make repos/upgrade` | `tronador repos upgrade` | Latest tag in the current major/minor line |
| `make repos/upgrade/major` | `tronador repos upgrade major` | Latest tag in the current major line |
| `.cloudopsworks/hooks/module_versions.sh` | `tronador iac module` | Report mode by default; add `--upgrade` to rewrite `?ref=` pins |

### Discover capabilities before assuming a command exists

`tronador project` resolves its capability set from the `.cloudopsworks/.iac` workspace marker, so the available capabilities differ between repository types. Never guess a capability name — list them:

```sh
tronador project detect        # Report the detected implementation and workspace marker
tronador project capabilities  # List every capability, its mutation class, and its flags
```

### Global flags

These apply across `tronador` commands:

- `--dry-run` — print the resolved tool pipeline without touching the working tree. **Run this first** for any destructive or file-mutating command.
- `--workdir <path>` — target a repository other than the current directory.
- `-v, --verbose` — verbose output, useful when diagnosing a failed template fetch or apply step.
- `--yes` — confirm destructive operations (`project clean`, `project clean-inputs`) non-interactively.
- `--json` — stable JSON output, for agents that need to parse results (`tronador project` only).

### Operations still driven by `make`

The `tronador` CLI does not yet expose branch and pull request workflows. The `make gitflow/*` targets remain the **only** supported way to create, publish, and finish branches:

- `make gitflow/feature/start-no-develop:<name>`, `make gitflow/feature/publish`, `make gitflow/feature/finish-no-develop`
- `make gitflow/hotfix/start`, `make gitflow/hotfix/publish`, `make gitflow/hotfix/finish`
- `make tag` / `make tag_local` — GitVersion-driven tag maintenance

Use them as documented in [Branch and Pull Request Procedure](#branch-and-pull-request-procedure). Everything else must go through `tronador`.

---

## 1. Handling a Freshly Created Repository from This Template

### What this repository is

This is a **Terragrunt/Terraform IaC project template** for managing multi-cloud infrastructure (AWS, Azure, GCP). When a new repository is created from this template, it must be initialized via a boilerplate tool before any infrastructure code is authored.

### Prerequisites

Ensure the following tools are available before proceeding:
- `tronador` — the CLI that drives every project operation; assume it is already installed on `PATH`
- `terragrunt` (v0.99+) — provisioned automatically by `tronador project init` if missing
- `boilerplate` — provisioned automatically by `tronador project init` if missing
- `gitversion` — required only for version tagging
- `make` — deprecated; still needed only for the `gitflow/*` targets

### Initialization Steps

#### Step 1: Run `tronador project init`

This is the **mandatory first step** for any fresh repository. It invokes the boilerplate engine against `.cloudopsworks/boilerplate/main/`, scaffolds the project configuration, and then formats the rendered HCL.

```sh
tronador project init --dry-run   # Review the resolved tool pipeline first
tronador project init
```

> Deprecated equivalent: `make init/project`. Do not use it.

You will be prompted for the following variables (or supply them via a `.inputs` file):

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

After `tronador project init` completes, the following files are created or updated:

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
  # Enable GitHub branch protection on the repository
  branchProtection: true

  # Conventional commits Ruleset — requires a paid GitHub plan (Pro/Team/Enterprise)
  conventionalCommitsEnabled: false
  enforceConventionalCommits: false

  # Custom commit message pattern enforcement
  enforceCustomCommitsPattern: false
  enforceCustomCommitsPatternRegex: "PROJECT-[0-9]+"

  gitFlow:
    enabled: false
    supportBranches: false

  # Named protected-source rules — see "Protected sources" below
  protectedSources:
    owners-only:
      paths:
        - ".github/**/*"
        - ".cloudopsworks/**/*"
        - "Makefile"
        - ".gitignore"
        - "root.hcl"
        - "common/**/*"
        - ".inputs*"
        - "state_conf.yaml"
        - "global-inputs.yaml"
        - "global-tags.json"
      allow:
        - <github-username-or-org/team>
      exempt:
        - <automation-account>

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

##### Protected sources

`protectedSources` is a **map of named rules**, not a flat list of glob patterns. The flat-list form is the old schema and is no longer honoured — repositories still carrying it must be migrated.

```yaml
# OLD — flat list, no longer supported
protectedSources:
  - "*.tf"
  - "*.tfvars"
  - OWNERS
  - Makefile
  - .github

# NEW — named rules
protectedSources:
  <rule-name>:
    paths:  [...]   # Glob patterns the rule guards
    allow:  [...]   # Principals permitted to change those paths
    exempt: [...]   # Principals the rule is not applied to at all
```

| Key | Meaning |
|---|---|
| `<rule-name>` | Arbitrary identifier for the rule. The template ships one rule named `owners-only`; define as many additional rules as the project needs. |
| `paths` | Glob patterns matched against the files changed in a pull request. Directory trees use `**/*`. |
| `allow` | Principals (GitHub usernames or `org/team`) permitted to modify the matched paths. Rendered by boilerplate from the `reviewers` input. |
| `exempt` | Principals the rule never applies to — typically automation accounts that must be able to commit template and CI updates unattended. Rendered by boilerplate from the `owners` input. |

The default `owners-only` rule guards the template-owned and boilerplate-generated files described in [Hard Rule: Protected Files](#hard-rule-protected-files--never-modify). Note that it now also guards `root.hcl`, `global-inputs.yaml`, `global-tags.json`, `.inputs*`, `state_conf.yaml`, and `common/**/*` — none of which were covered by the old flat list. Agents editing any of those paths must expect the pull request to require an `allow`-listed reviewer.

##### Commit message enforcement

| Key | Default | Effect |
|---|---|---|
| `conventionalCommitsEnabled` | `false` | Creates the GitHub Ruleset for conventional commits. Requires a paid GitHub plan — has no effect on Free plans. |
| `enforceConventionalCommits` | `false` | Enforces the conventional commit format on commit messages. |
| `enforceCustomCommitsPattern` | `false` | Enforces `enforceCustomCommitsPatternRegex` on commit messages. |
| `enforceCustomCommitsPatternRegex` | `"PROJECT-[0-9]+"` | The regex applied when `enforceCustomCommitsPattern` is `true` — for example, requiring a Jira ticket key in every commit message. |

Enabling these does not remove the `+semver:` annotation requirement described in [Semver Commit Annotations](#semver-commit-annotations) — GitVersion still reads that annotation from the merge commit.

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
tronador project lint         # Validates Terragrunt and Terraform/OpenTofu configuration
tronador iac module           # Reports stale module ?ref= version pins
tronador project clean --yes  # Removes caches and plan artifacts before committing
```

> Deprecated equivalents: `make lint`, `make clean`. Do not use them.

#### Step 6: Initial commit workflow

Branch operations have no `tronador` equivalent yet, so the `make gitflow/*` targets below remain the supported path — see [Operations still driven by `make`](#operations-still-driven-by-make).

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

The following files are **boilerplate-generated** and must never be modified directly. They are regenerated by `tronador project init` from stored inputs and any manual edits will be overwritten:

```
root.hcl
global-inputs.yaml
.inputs
.inputs_mod
.cloudopsworks/.inputs_cicd
```

### Upgrade Procedure

#### Step 1: Run the appropriate upgrade command

Use the `tronador repos` commands. They run the full workflow — detect the current template type, resolve the target tag, fetch and apply the template, update CICD metadata, and commit the result — without depending on `make` or the network-fetched `.tronador` accelerator include.

```sh
tronador repos available          # List template versions available for upgrade
tronador repos upgrade --dry-run  # Preview the upgrade scope without touching the working tree
tronador repos upgrade            # Latest tag in the current major/minor line
tronador repos upgrade major      # Latest tag in the current major line
tronador repos upgrade <version>  # Explicit tag or branch, e.g. `tronador repos upgrade v5.12.0`
tronador repos upgrade master     # Upgrade from the template repository's master branch tip
```

> Deprecated equivalents: `make repos/upgrade` and `make repos/upgrade/major`. Do not use them.

These commands pull changes from the upstream template. Protected files will be updated automatically — do not interfere with those changes.

Useful flags (apply to all `tronador repos *` subcommands):

- `--dry-run` — preview what the upgrade would change without touching the working tree; run this before the real upgrade to review scope.
- `--workdir <path>` — target a repository other than the current directory.
- `-v, --verbose` — verbose output, useful when diagnosing a failed template fetch or apply step.
- `--config <path>` — override the embedded repos JSON config.
- `--gh <path>` / `--git <path>` — use explicit `gh` and `git` executables instead of the ones on `PATH`.

Other `tronador repos` subcommands:

| Command | Purpose |
|---|---|
| `tronador repos available` | List template repository versions available for upgrade |
| `tronador repos recover` | Restore repository files from the template without committing |
| `tronador repos push` | Stage and commit template upgrade changes |
| `tronador repos cicd update` | Update the CICD pipeline footer versioning |
| `tronador repos clean` | Clean repository workflows |

`tronador repos upgrade` stages and commits the applied changes itself (the same effect as `tronador repos push`), so continue at **Step 2** below to re-run `tronador project init` and review the diff. The same protected-files rule applies: do not hand-edit anything the upgrade wrote under `.cloudopsworks/boilerplate/`, `.cloudopsworks/hooks/`, `.cloudopsworks/_VERSION`, `.cloudopsworks/LICENSE`, `.cloudopsworks/labeler.yml`, or `.github/`.

#### Step 2: Re-run `tronador project init`

After the upgrade, re-apply the boilerplate to regenerate `root.hcl`, `global-inputs.yaml`, and other templated files using the existing stored inputs:

```sh
tronador project init
```

`tronador project init` automatically picks up `.inputs`, `.inputs_mod`, `.cloudopsworks/.inputs_cicd`, and `.inputs_state` if they exist, so no re-prompting occurs.

#### Step 3: Review generated diffs

Carefully diff the regenerated files against previous versions. The boilerplate may:
- Add new required blocks to `root.hcl`
- Add new keys to `global-inputs.yaml`
- Update provider version constraints
- Restructure `.cloudopsworks/cloudopsworks-ci.yaml` — in particular, `protectedSources` migrates from a flat list of globs to a map of named rules, and the commit-enforcement keys (`conventionalCommitsEnabled`, `enforceConventionalCommits`, `enforceCustomCommitsPattern`, `enforceCustomCommitsPatternRegex`) are added. See [Protected sources](#protected-sources) and [Commit message enforcement](#commit-message-enforcement) before reconciling this file — do not restore the old flat list.

Merge any project-specific customizations that were present in the old versions of these files back into the newly generated ones. After merging customizations, re-format any changed HCL files:

```sh
tronador project format
```

#### Step 4: Validate

```sh
tronador project lint         # Catches HCL syntax errors
tronador iac module           # Reports stale module ?ref= version pins
tronador project clean --yes  # Clears caches and plan artifacts
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
- Always use `make gitflow/*` targets for branch operations — never raw `git checkout -b` or `git push -u origin`. These targets handle dependency checks, naming conventions, and upstream tracking automatically. Branch workflows are the one remaining exception to the `make` deprecation; see [Operations still driven by `make`](#operations-still-driven-by-make).
- Plan consistently and thoroughly before starting any work.
- Use `gh` CLI for PR management. When waiting for CI checks to pass, use `gh pr checks <PR_NUMBER> --watch`.

#### Branch naming and creation

All changes must be made on a dedicated branch, never directly on `master`. Use the `make gitflow/*` targets — never raw `git checkout -b`. These targets have no `tronador` equivalent yet and remain the supported path.

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
- [ ] HCL formatted (`tronador project format`)
- [ ] `tronador project lint` passes with no errors
- [ ] `tronador project clean --yes` run before committing (no cache artifacts staged)
- [ ] `+semver:` annotation included in PR body matching expected version impact
- [ ] No protected files modified (`.cloudopsworks/boilerplate/`, `.cloudopsworks/hooks/`, `.cloudopsworks/_VERSION`, `.cloudopsworks/LICENSE`, `.cloudopsworks/labeler.yml`, `.github/`)
- [ ] No boilerplate-generated files modified directly (`root.hcl`, `global-inputs.yaml`, `.inputs`, `.inputs_mod`, `.cloudopsworks/.inputs_cicd`)
- [ ] Changes reviewed for correctness in the target environment(s)
- [ ] CI plan output reviewed before merging
```

The CI plan workflow will run automatically against the PR. Do not merge until the plan output has been reviewed and approved by the required reviewers defined in `.cloudopsworks/cloudopsworks-ci.yaml`.

### Module Version Checks

The `.cloudopsworks/hooks/module_versions.sh` hook runs automatically in CI to detect outdated `?ref=` version pins in `terragrunt.hcl` files. Locally, use `tronador iac module` rather than invoking the hook directly — it reads the same `.cloudopsworks/.iac` workspace marker and can apply the updates for you.

```sh
tronador iac module                          # Report available patch/minor/major targets, change nothing
tronador iac module --path environments/dev  # Restrict module discovery to one subtree
tronador iac module --upgrade                # Rewrite eligible ?ref= pins to the latest patch (default tier)
tronador iac module --upgrade --minor        # Latest eligible minor in the current major series
tronador iac module --upgrade --major        # Latest eligible major; falls back to the highest eligible minor
tronador iac module --fix-prefix             # Add missing git:: prefixes without changing refs
```

Flag notes:

- `--minor` and `--major` require `--upgrade` and are mutually exclusive.
- `--alpha` / `--beta` permit prerelease tags to be selected.
- `-r, --report-ghaction` emits GitHub Actions warning annotations; `-c, --comment-pr-num <n>` posts the findings as a pull request comment.
- `--dry-run` previews the rewrite without touching files.

When modules are flagged as outdated:

1. Start a hotfix branch:
   ```sh
   make gitflow/hotfix/start
   ```
2. Apply the update, or edit the `source` URL's `?ref=` value by hand to the recommended version shown in the CI warning:
   ```sh
   tronador iac module --upgrade
   ```
3. Format the changed files:
   ```sh
   tronador project format
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

When CI/CD settings need to change (new environments, reviewer changes, runner configuration, protected sources, commit message enforcement):

1. Edit `.cloudopsworks/cloudopsworks-ci.yaml` only.
2. Do not edit `.github/workflows/` files directly.
3. Commit the change and let the repository governance automation pick it up.

Schema notes for agents editing this file — [Step 3: Configure `cloudopsworks-ci.yaml`](#step-3-configure-cloudopsworks-ciyaml) holds the full reference:

- `protectedSources` is a **map of named rules** (`<rule-name>: { paths, allow, exempt }`), not a flat list of globs. A repository still carrying the flat-list form is on the old schema; `tronador repos upgrade` followed by `tronador project init` regenerates it. Never reintroduce the flat list.
- The default `owners-only` rule guards `.github/**/*`, `.cloudopsworks/**/*`, `Makefile`, `.gitignore`, `root.hcl`, `common/**/*`, `.inputs*`, `state_conf.yaml`, `global-inputs.yaml`, and `global-tags.json`. Pull requests touching those paths need an `allow`-listed reviewer, so plan changes to them accordingly.
- `allow` is rendered from the boilerplate `reviewers` input and `exempt` from the `owners` input, so changing `reviewers` or `owners` and re-running `tronador project init` rewrites the rule.
- `conventionalCommitsEnabled`, `enforceConventionalCommits`, `enforceCustomCommitsPattern`, and `enforceCustomCommitsPatternRegex` control commit message rulesets. The Ruleset-based options require a paid GitHub plan and silently do nothing on Free plans.
- Changes to this file are a PATCH change — use a `hotfix/` branch and `+semver: patch`.

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
| Template upgrade follow-up (`tronador repos upgrade`) | `hotfix/` | PATCH | `+semver: patch` |
| HCL formatting correction only | `hotfix/` | PATCH | `+semver: patch` |

### Feature Branch Workflow (MINOR / MAJOR changes)

```sh
# 1. Start branch from master
make gitflow/feature/start-no-develop:<feature-name>

# 2. Implement changes, then format any changed HCL files
tronador project format

# 3. Validate
tronador project lint

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
tronador project format

# 3. Validate
tronador project lint

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
