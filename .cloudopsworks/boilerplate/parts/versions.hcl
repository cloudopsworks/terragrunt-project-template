{{- define "terragrunt_versions" }}
iam_role                      = local.global_vars.default.sts_role_arn
iam_assume_role_session_name  = "terragrunt"
terraform_version_constraint  = ">= 1.7 , <1.9"
terragrunt_version_constraint = ">= 0.72"
{{- end }}