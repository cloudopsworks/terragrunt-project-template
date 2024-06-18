# terraform-project-template
Terraform Project Build Automation Template
* Prerequisites:
  * Available AWS profile
  * AWS Cli
  * aws-vault binary
* This initial setup creates S3 bucket for terraform state in main account.
## Sample backend config (have it remote instead of local)
### Using SSM Parameter Store
* take in account _*< ssm parameter >*_ should be an existeng SSM parameter in Parameter Store.
* Usually will be declared on _*cloudopsworks-ci.yaml*_
* You will need access to the SSM Parameter Store to r etrieve the object.
```shell
aws-vault exec <profile> -- aws ssm get-parameters \
  --names "<ssm parameter>" --query "Parameters[0].Value" \
  --output text > /tmp/remote.tfbackend
```

## Terraform operations
### Terraform init
```shell
aws-vault exec <profile> -- terraform init -backend-config=/tmp/remote.tfbackend
```

### Terraform workspace selection
```shell
aws-vault exec <profile> -- terraform workspace select <workspace name>
```

### Terraform plan output
```shell
aws-vault exec <profile> -- terraform plan -var-file tfvars/<env>.terraform.tfvars -out /tmp/plan.out
```

### Terraform apply
```shell
aws-vault exec <profile> -- terraform apply /tmp/plan.out
```

