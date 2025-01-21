{{ template "terragrunt_vars" }}

# Generate global provider block
generate "provider" {
  path      = "provider.g.tf"
  if_exists = "overwrite_terragrunt"
  contents  = <<EOF
provider "aws" {
  region = "${local.global_vars.default.region}"
  assume_role {
    role_arn     = "${local.global_vars.default.sts_role_arn}"
    session_name = "terragrunt"
  }
}
EOF
}

# Generate remote state block
remote_state {
  backend = "s3"
  generate = {
    path      = "remote_state.g.tf"
    if_exists = "overwrite_terragrunt"
  }
  config = {
    bucket               = local.state_conf.s3.bucket
    region               = local.state_conf.s3.region
    workspace_key_prefix = "workspaces"
    encrypt              = true
    kms_key_id           = local.state_conf.s3.kms_key_id
    dynamodb_table       = local.state_conf.s3.dynamodb_table
    key                  = "${basename(get_repo_root())}/${path_relative_to_include()}/terraform.tfstate"
  }
}

{{ template "terragrunt_version" }}