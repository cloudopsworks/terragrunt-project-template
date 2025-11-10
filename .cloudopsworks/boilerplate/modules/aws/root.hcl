{{- template "terragrunt_vars" . }}

# Generate global provider block
generate "provider" {
  path      = "provider.g.tf"
  if_exists = "overwrite_terragrunt"
  contents  = <<EOF
  provider "aws" {
    region = "${local.region}"
{{- if not .enable_assume_role_on_root }}
{{- template "provider_assume_role" . }}
{{- end }}
  }
EOF
}

# Generate remote state block
generate "backend" {
  path      = "remote_state.g.tf"
  if_exists = "overwrite_terragrunt"
  contents = <<EOF
{{- if eq .state_type "s3" -}}
{{- template "state_config_s3" . }}
{{- end -}}
{{- if eq .state_type "gcs" -}}
{{- template "state_config_gcs" . }}
{{- end -}}
{{- if eq .state_type "azurerm" -}}
{{- template "state_config_azurerm" . }}
{{- end -}}
EOF
}

{{- if .enable_assume_role_on_root -}}
{{- template "root_assume_role" . }}
{{- end -}}
{{- template "terragrunt_versions" . }}