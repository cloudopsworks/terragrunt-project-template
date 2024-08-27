locals {
  local_vars  = yamldecode(file("./inputs.yaml"))
  env_vars    = yamldecode(file(find_in_parent_folders("env-inputs.yaml")))
  global_vars = yamldecode(file(find_in_parent_folders("global-inputs.yaml")))
  env_tags    = jsondecode(file(find_in_parent_folders("env-tags.json")))
  global_tags = jsondecode(file(find_in_parent_folders("global-tags.json")))
  local_tags  = jsondecode(file("./local-tags.json"))

  tags = merge(
    local.global_tags,
    local.env_tags,
    local.local_tags
  )
}

include {
  path = find_in_parent_folders()
}

terraform {
  source = "github.com/cloudopsworks/terraform-module-aws-organization-basic-iam.git//?ref=master"
}

inputs = {
  parent_account_id = local.global_vars.organization.account_id
  account_id        = local.global_vars.account.id
  org               = local.env_vars.org
  secrets_manager   = true
  extra_tags        = local.tags
}