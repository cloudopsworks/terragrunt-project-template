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

terraform {
  #source = "git::https://github.com/cloudopsworks/terraform-module-aws-organizations.git//?ref=v2.0.4"
  source = "git::https://github.com/cloudopsworks/terraform-module-aws-organizations.git//?ref=v2.2.3"
}

inputs = {
  organization_name                 = local.local_vars.org.name
  fintech_name                      = local.local_vars.org.fintech_name
  environment_type                  = local.local_vars.org.environment_type
  environment_name                  = local.local_vars.org.environment_name
  organization_email                = local.local_vars.org.email
  organization_allow_billing_access = true
  extra_tags                        = local.tags
}