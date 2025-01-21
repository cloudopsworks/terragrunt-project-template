{{- define "terragrunt_vars" }}
# on Plan generate plan files in each module
terraform {
  extra_arguments "plan_file" {
    commands  = ["plan"]
    arguments = ["-out=${get_terragrunt_dir()}/tfplan.out"]
  }
}
# load local variables from state_conf.yaml
locals {
  state_conf  = yamldecode(file("./state_conf.yaml"))
  global_vars = yamldecode(file("./global-inputs.yaml"))
  global_tags = jsondecode(file("./global-tags.json"))
}
{{- end }}