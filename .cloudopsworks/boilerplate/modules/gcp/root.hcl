{{- template "terragrunt_vars" . }}

# Generate global provider block
generate "provider" {
  path      = "provider.g.tf"
  if_exists = "overwrite_terragrunt"
  contents  = <<EOF
provider "google" {
  project                     = "${local.project}"
  region                      = "${local.region}"
  impersonate_service_account = "${local.impersonate_sa}"
}
provider "google-beta" {
  project                     = "${local.project}"
  region                      = "${local.region}"
  impersonate_service_account = "${local.impersonate_sa}"
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