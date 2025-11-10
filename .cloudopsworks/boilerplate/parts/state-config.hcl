{{- define "state_config_s3" -}}
terraform {
  backend "s3" {
    bucket         = "${local.state_conf.s3.bucket}"
    region         = "${local.state_conf.s3.region}"
    kms_key_id     = "${local.state_conf.s3.kms_key_id}"
    dynamodb_table = "${local.state_conf.s3.dynamodb_table}"
    key            = "${local.state_prefix}/terraform.tfstate"
  }
}
{{- end -}}
{{- define "state_config_gcs" -}}
terraform {
  backend "gcs" {
    bucket             = "${local.state_conf.gcs.bucket}"
    kms_encryption_key = "${local.state_conf.gcs.kms_encryption_key}"
    prefix             = "${local.state_prefix}/terraform.tfstate"
  }
}
{{- end -}}
{{- define "state_config_azurerm" -}}
terraform {
  backend "azurerm" {
    use_msi              = "${local.state_conf.azurerm.use_msi}"
    use_azuread_auth     = "${local.state_conf.azurerm.use_azuread_auth}"
    tenant_id            = "${local.state_conf.azurerm.tenant_id}"
    subscription_id      = "${local.state_conf.azurerm.subscription_id}"
    resource_group_name  = "${local.state_conf.azurerm.resource_group_name}"
    storage_account_name = "${local.state_conf.azurerm.storage_account_name}"
    container_name       = "${local.state_conf.azurerm.container_name}"
    key                  = "${local.state_prefix}/terraform.state"
  }",
}",
{{- end -}}