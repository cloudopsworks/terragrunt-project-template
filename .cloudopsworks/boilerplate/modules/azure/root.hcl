{{- template "terragrunt_vars" . }}

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
generate "backend" {
  path      = "remote_state.g.tf"
  if_exists = "overwrite_terragrunt"
  contents = <<EOF
{{- if eq .state_type "s3" }}
{{ template "state_config_s3" . }}
{{- end }}
{{- if eq .state_type "gcs" }}
{{ template "state_config_gcs" . }}
{{- end }}
{{- if eq .state_type "azurerm" }}
{{ template "state_config_azurerm" . }}
{{- end }}
EOF
}

{{- template "terragrunt_versions" . }}