# Agent Guidelines — Terragrunt Project Template

This document provides agentic guidelines for working with repositories created from or derived from the **cloudopsworks/terragrunt-project-template**. It covers two distinct operating contexts.

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
    enabled: true
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
    develop:
      env: dev
    release:
      env: production
    test:
      env: test
    prerelease:
      env: uat
```

Adjust `reviewers`, `owners`, `requiredReviewers`, and CD deployment mappings as needed.

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

1. Commit all generated and authored files on the `develop` branch.
2. Open a PR from `develop` → `master`.
3. The CI plan workflow will run automatically on the PR.
4. After approval and merge, the CD workflow can deploy to target environments.

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

Merge any project-specific customizations that were present in the old versions of these files back into the newly generated ones.

#### Step 4: Validate

```sh
make lint    # Catches HCL syntax errors and stale module version refs
make clean   # Clears caches and plan artifacts
```

#### Step 5: Commit only non-protected files

Stage and commit only files outside the protected paths. Do not commit changes to `.github/`, `.cloudopsworks/boilerplate/`, `.cloudopsworks/hooks/`, `.cloudopsworks/_VERSION`, `.cloudopsworks/LICENSE`, or `.cloudopsworks/labeler.yml` unless they arrived directly from the upstream merge and are unmodified.

### Branch and Pull Request Procedure

#### Branch naming

All changes — including upgrade follow-up work — must be made on a dedicated branch, never directly on `master` or `develop`:

```
feature/<short-description>   # New infrastructure modules or capabilities
fix/<short-description>        # Bug fixes, corrections, configuration repairs
```

Examples:
```sh
git checkout -b feature/add-spoke-vpc-dev
git checkout -b fix/missing-assume-role-arn
```

#### Opening a pull request

After committing changes to the feature or fix branch, open a pull request targeting `master`. Use the following format for the PR body:

```markdown
## Summary
<One or two sentences describing what this PR does and why.>

## Changes
- <Main change 1>
- <Main change 2>
- <Main change 3>

## Checklist
- [ ] `make lint` passes with no errors
- [ ] `make clean` run before committing (no cache artifacts staged)
- [ ] No protected files modified (`.cloudopsworks/boilerplate/`, `.cloudopsworks/hooks/`, `.cloudopsworks/_VERSION`, `.cloudopsworks/LICENSE`, `.cloudopsworks/labeler.yml`, `.github/`)
- [ ] No boilerplate-generated files modified directly (`root.hcl`, `global-inputs.yaml`, `.inputs`, `.inputs_mod`, `.cloudopsworks/.inputs_cicd`)
- [ ] Changes reviewed for correctness in the target environment(s)
```

The CI plan workflow will run automatically against the PR. Do not merge until the plan output has been reviewed and approved by the required reviewers defined in `.cloudopsworks/cloudopsworks-ci.yaml`.

### Module Version Checks

The `.cloudopsworks/hooks/module_versions.sh` hook runs automatically in CI to detect outdated `?ref=` version pins in `terragrunt.hcl` files. When modules are flagged as outdated:

1. Open the relevant `terragrunt.hcl` file.
2. Update the `source` URL's `?ref=` value to the recommended version shown in the CI warning.
3. Do not modify the hook script itself.

### CI/CD Governance Updates

When CI/CD settings need to change (new environments, reviewer changes, runner configuration):

1. Edit `.cloudopsworks/cloudopsworks-ci.yaml` only.
2. Do not edit `.github/workflows/` files directly.
3. Commit the change and let the repository governance automation pick it up.
