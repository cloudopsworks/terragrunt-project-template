{{- define "provider_assume_role" }}
    assume_role {
      role_arn     = "${local.global_vars.default.sts_role_arn}"
      session_name = "terragrunt"
    }
{{- end }}