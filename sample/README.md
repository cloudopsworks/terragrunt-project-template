## Sample Project Structure
This is a sample project structure that manages:
- **/global** Organization Account Creation & IAM Role Management
- **/networking** A Landing VPC Setup, Transit gateway and DNS Management + Rule Sharing
- **/environments** A Sample DEV environment with VPC Transit Gateway Attachments & Local DNS management and Landing DNS integration
These modules can be used at root level instead of under **sample** directory. The sample directory is just for demonstration purposes.

### About Templates
Root folder has 3 templates:
- **global-inputs.yaml_template**:
  - Global inputs has plenty of variables to be set up in order to be sampled
    Sample variables that has use in the sample project:
    ```yaml
    organization:
      id: r-XXXX
      account_id: 123456789012
      terraform:
        group_name: terraform-access-group
    ```
  - Most important is to set up the default region and STS Role ARN that will run the terragrunt commands
    ```yaml
    default:
      region: <AWS_REGION>
      sts_role_arn: arn:aws:iam::<ACCOUNT_ID>:role/TerraformAccessRole
    ```
- **global-tags.json_template**:
  - These tags defined in this JSON will be injected on all resources being created
  - Sample tags:
    ```json
    {
      "maintainer-id": "cloudopsworks-bot",
      "maintainer-email": "bot@cloudops.works",
      "iac-project-name": "terragrunt-project-template",
      "zone-ownership-by": "shared",
      "zone-managed-by": "owner"
    }
    ```
- **state_conf.yaml_template**: