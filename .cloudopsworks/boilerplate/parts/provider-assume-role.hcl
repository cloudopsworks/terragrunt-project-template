{{- define "provider_assume_role" }}
    # Assumed Role on terragrunt root is not enabled:
    assume_role {
      role_arn     = "${local.sts_role_arn}"
      session_name = "terragrunt"
    }
{{- end }}