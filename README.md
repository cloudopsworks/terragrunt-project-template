# terragrunt-project-template
Terraform Project Build Automation Template
* Prerequisites:
  * AWS
    * Available AWS profile
    * AWS Cli
      * aws-vault binary
  * Azure
    * Available Service account with access and permissions
    * Azure Cli
  * Google Cloud
    * Available Service account with access and permissions
    * gcloud Cli
  * Terragrunt Binary
  * OpenTofu Binary
## Terragrunt operations
### Plan output
```shell
terragrunt --terragrunt-non-interactive --terragrunt-working-dir <module-path> plan
```

### Plan apply
```shell
terragrunt --terragrunt-non-interactive --terragrunt-working-dir <module-path> apply tfplan.out
```

