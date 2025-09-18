{{- define "root_assume_role" }}
iam_role                      = local.global_vars.default.sts_role_arn
iam_assume_role_session_name  = "terragrunt"
{{- end }}