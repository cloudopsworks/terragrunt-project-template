{{- template "terragrunt_vars" }}

# Generate global provider block
generate "provider" {
  path      = "provider.g.tf"
  if_exists = "overwrite_terragrunt"
  contents  = <<EOF
  provider "azurerm" {
    features                        = {}
    subscription_id                 = "${local.global_vars.default.subscription}"
    use_msi                         = ${try(local.global_vars.default.use_msi, false)}
    resource_provider_registrations = "${try(local.global_vars.default.resource_provider_registrations, "none")}"
  }
EOF
}

# Generate remote state block
remote_state {
  backend = "azurerm"
  generate = {
    path = "remote_state.g.tf"
    if_exists = "overwrite_terragrunt"
  }
  config = {
    use_azuread_auth     = true
    use_msi              = try(local.global_vars.default.use_msi, false)
    subscription_id      = local.state.conf.azurerm.subscription_id
    resource_group_name  = local.state.conf.azurerm.resource_group_name
    storage_account_name = local.state.conf.azurerm.storage_account_name
    container_name       = local.state.conf.azurerm.container_name
    key                  = "${basename(get_repo_root())}/${path_relative_to_include()}/terraform.tfstate"
  }
}

{{- template "terragrunt_versions" }}