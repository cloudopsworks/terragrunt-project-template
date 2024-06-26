locals {
  local_vars  = yamldecode(file("./inputs.yaml"))
  spoke_vars  = yamldecode(file(find_in_parent_folders("spoke-inputs.yaml")))
  region_vars = yamldecode(file(find_in_parent_folders("region-inputs.yaml")))
  env_vars    = yamldecode(file(find_in_parent_folders("env-inputs.yaml")))
  global_vars = yamldecode(file(find_in_parent_folders("global-inputs.yaml")))

  local_tags  = jsondecode(file("./local-tags.json"))
  spoke_tags  = jsondecode(file(find_in_parent_folders("spoke-tags.json")))
  region_tags = jsondecode(file(find_in_parent_folders("region-tags.json")))
  env_tags    = jsondecode(file(find_in_parent_folders("env-tags.json")))
  global_tags = jsondecode(file(find_in_parent_folders("global-tags.json")))

  tags = merge(
    local.global_tags,
    local.env_tags,
    local.region_tags,
    local.spoke_tags,
    local.local_tags
  )
}

include {
  path = find_in_parent_folders()
}

#local provider configuration
generate "region_provider" {
  path      = "provider.l.tf"
  if_exists = "overwrite_terragrunt"
  contents  = <<EOF
provider "aws" {
  alias  = "default"
  region = "${local.region_vars.region}"
  assume_role {
    role_arn     = "${local.region_vars.sts_role_arn}"
    session_name = "terragrunt-local"
  }
}
EOF
}

terraform {
  source = "github.com/cloudopsworks/terraform-module-aws-vpc-setup.git//?ref=master"
}

inputs = {
  is_hub               = true
  org                  = local.env_vars.org
  vpc_cidr             = local.local_vars.vpc.cidr_block
  availability_zones   = local.local_vars.vpc.availability_zones
  public_subnets       = local.local_vars.vpc.subnet_cidr_blocks.public
  private_subnets      = local.local_vars.vpc.subnet_cidr_blocks.private
  database_subnets     = local.local_vars.vpc.subnet_cidr_blocks.database
  vpn_accesses         = local.local_vars.vpn_accesses
  create_bastion       = local.local_vars.bastion.create
  bastion_size         = local.local_vars.bastion.vm_size
  bastion_storage      = local.local_vars.bastion.disk_size
  dhcp_dns             = local.local_vars.vpc.dhcp_option.dns
  spoke_def            = local.spoke_vars.hub
  internal_allow_cidrs = local.local_vars.vpc.internal_allow_cidrs
  endpoint_services    = local.local_vars.endpoint_services
  extra_tags           = local.tags
}