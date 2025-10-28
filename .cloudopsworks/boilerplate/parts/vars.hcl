{{- define "terragrunt_vars" }}
# load local variables from state_conf.yaml
locals {
  state_conf  = yamldecode(file("./state_conf.yaml"))
  global_vars = yamldecode(file("./global-inputs.yaml"))
  global_tags = jsondecode(file("./global-tags.json"))
  script_path = "${get_parent_terragrunt_dir()}/.cloudopsworks/hooks"
  dotted_path = replace(path_relative_to_include(), "/", ".")
  # Allow change STS Role at each Level - region and spoke are optional configs searched in parent folders
  region_file  = find_in_parent_folders("region-inputs.yaml", "")
  region_vars  = local.region_file != "" ? yamldecode(file(local.region_file)) : {}
  spoke_file   = find_in_parent_folders("spoke-inputs.yaml", "")
  spoke_vars   = local.spoke_file != "" ? yamldecode(file(local.spoke_file)) : {}
{{- if eq .target_cloud "aws" }}
  region       = try(local.region_vars.region, local.global_vars.default.region)
  sts_role_arn = try(local.region_vars.sts_role_arn, local.spoke_vars.sts_role_arn, local.global_vars.default.sts_role_arn)
{{- end }}
{{- if eq .target_cloud "gcp" }}
  project            = local.global_vars.project.id
  region             = try(local.region_vars.region, local.global_vars.default.region)
  impersonate_sa     = try(local.region_vars.impersonate_sa, local.spoke_vars.impersonate_sa, local.global_vars.default.impersonate_sa)
{{- end }}
}
# on Plan generate plan files in each module
terraform {
  extra_arguments "plan_file" {
    commands  = ["plan"]
    arguments = ["-out=${get_terragrunt_dir()}/tfplan.out"]
  }

  after_hook "feed_outputs" {
    commands = ["apply","refresh"]
    execute  = ["/bin/bash", "${local.script_path}/parse_outputs.sh", local.dotted_path, "${get_parent_terragrunt_dir()}"]
  }
}
{{- end }}