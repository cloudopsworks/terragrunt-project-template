locals {
  local_vars  = yamldecode(file("./inputs.yaml"))
  global_vars = yamldecode(file(find_in_parent_folders("global-inputs.yaml")))
  global_tags = jsondecode(file(find_in_parent_folders("global-tags.json")))
  local_tags  = jsondecode(file("./local-tags.json"))

  tags = merge(
    local.global_tags,
    local.local_tags
  )
}

include {
  path = find_in_parent_folders()
}

dependencies {
  paths = ["../org"]

}

dependency "org" {
  config_path = "../org"
  # Configure mock outputs for the `validate` command that are returned when there are no outputs available (e.g the
  # module hasn't been applied yet.
  mock_outputs_allowed_terraform_commands = ["validate"]
  mock_outputs = {
    account_id             = "123456789012"
    account_arn            = "arn:aws:organizations::123456789012:account/o-123456789012/a-123456789012"
    account_name           = "Org-Name"
    account_assume_role_id = "arn:aws:iam::123456789012:role/OrganizationAccountAccessRole"
    account_console_url    = "https://123456789012.signin.aws.amazon.com/console"
    account_tags = {
      organization_name = "Org"
      organization_unit = "Unit"
      environment_name  = "Env_Name"
      environment_type  = "Env_type"

    }
  }
}

# generate global provider block
generate "provider_local" {
  path      = "provider.l.tf"
  if_exists = "overwrite_terragrunt"
  contents  = <<EOF
provider "aws" {
  alias  = "default"
  region = "${local.global_vars.default.region}"
  assume_role {
    #role_arn     = "${local.global_vars.default.sts_role_arn}"
    session_name = "terragrunt"
  }
}
provider "aws" {
  alias  = "account"
  region = "${local.global_vars.default.region}"
  assume_role {
    role_arn     = "${dependency.org.outputs.account_assume_role_id}"
    session_name = "terragrunt-local"
  }
}
EOF
}

terraform {
  source = "github.com/cloudopsworks/terraform-module-aws-organization-basic-iam.git//?ref=master"
}

inputs = {
  parent_account_id = local.global_vars.organization.account_id
  account_id        = dependency.org.outputs.account_id
  allowsts_group    = local.global_vars.organization.terraform.group_name
  tags              = dependency.org.outputs.account_tags
  extra_tags        = local.tags
}