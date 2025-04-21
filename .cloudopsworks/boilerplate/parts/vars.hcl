{{- define "terragrunt_vars" }}
# load local variables from state_conf.yaml
locals {
  state_conf  = yamldecode(file("./state_conf.yaml"))
  global_vars = yamldecode(file("./global-inputs.yaml"))
  global_tags = jsondecode(file("./global-tags.json"))
  script_path = "${get_parent_terragrunt_dir()}/.cloudopsworks/hooks/parse_outputs.sh"
  dotted_path = replace(path_relative_to_include(), "/", ".")
  region_vars = try(yamldecode(file("${path_relative_to_include()}/../region-inputs.yaml")), yamldecode(file("${path_relative_to_include()}/../../region-inputs.yaml")), {
    region = local.global_vars.default.region
  })
}
# on Plan generate plan files in each module
terraform {
  extra_arguments "plan_file" {
    commands  = ["plan"]
    arguments = ["-out=${get_terragrunt_dir()}/tfplan.out"]
  }

  after_hook "feed_outputs" {
    commands = ["apply","refresh"]
    execute  = ["/bin/bash", local.script_path, local.dotted_path, "${get_parent_terragrunt_dir()}"]
  }
}
{{- end }}