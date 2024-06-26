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
  path      = "provider.r.tf"
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

dependencies {
  paths = [
    "../vpc",
    "../../../../../../networking/landing/useast1/hub-000/dns"
  ]
}

dependency "vpc" {
  config_path = "../vpc"
  # Configure mock outputs for the `validate` command that are returned when there are no outputs available (e.g the
  # module hasn't been applied yet.
  mock_outputs_allowed_terraform_commands = ["validate"]
  mock_outputs = {
    bastion_key = [
      "ssh-rsa AQWERTYUIOPASDFGHJKL1234567890"
    ]
    bastion_public_address = [
      "1.1.1.1-ip.com",
    ]
    bastion_public_ip = [
      "1.1.1.1",
    ]
    bastion_security_group_id = "sg-12345678901234"
    database_subnet_group     = "vpc-network-hub-aaaa-000-usea1"
    database_subnets = [
      "subnet-abcdef123456789",
      "subnet-abcdef123456789",
      "subnet-abcdef123456789",
    ]
    nat_address = tolist([
      "2.2.2.2",
    ])
    private_subnets = [
      "subnet-01234567890123456",
      "subnet-01234567890123456",
      "subnet-01234567890123456",
    ]
    private_route_table_ids = [
      "rtb-1234567890",
      "rtb-1234567890",
      "rtb-1234567890",
    ]
    public_subnets = [
      "subnet-01234567890123456",
      "subnet-01234567890123456",
    ]
    ssh_admin_security_group_id = "sg-abcdef1234567"
    vpc_id                      = "vpc-12345678901234"
    vpn_accesses = tolist([
      "1.2.3.4/32",
      "5.6.7.8/32",
    ])
    flowlogs_role_arn = ""
    cloudwatch_log_group = {
      arn  = "arn:aws:logs:us-east-1:123456789012:log-group:network/hub/hub-000/vpc-12345678901234"
      name = "network/hub/hub-000/vpc-12345678901234"
    }
  }
}

dependency "rootdns" {
  config_path                             = "../../../../../../networking/landing/useast1/hub-000/dns"
  mock_outputs_allowed_terraform_commands = ["validate"]
  mock_outputs = {
    resolver_rule_id = "rslvr-12345678901234"
  }
}

terraform {
  source = "github.com/cloudopsworks/terraform-module-aws-dns-setup.git//?ref=master"
}

inputs = {
  is_hub             = false
  org                = local.env_vars.org
  spoke_def          = local.spoke_vars.spoke
  zones              = local.local_vars.zones
  vpc_id             = dependency.vpc.outputs.vpc_id
  vpc_cidr_block     = dependency.vpc.outputs.vpc_cidr_block
  subnet_ids         = dependency.vpc.outputs.private_subnets
  enable_auto_accept = local.local_vars.enable_auto_accept
  ram                = local.local_vars.ram
  shared = {
    ram_shares     = dependency.rootdns.outputs.ram.resource_shares
    resolver_rules = dependency.rootdns.outputs.resolver_rules.inbound
  }
  dns_vpc = {
    vpc_id     = dependency.rootdns.outputs.dns_vpc.vpc_id
    vpc_region = dependency.rootdns.outputs.dns_vpc.vpc_region
    vpc_region = dependency.rootdns.outputs.dns_vpc.vpc_region
  }
  extra_tags = local.tags
}