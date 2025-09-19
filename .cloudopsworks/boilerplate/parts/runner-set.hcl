{{- define "runner_set" }}
# GitHub Runner Set affinity - if set will tie the runner to a specific set
runner_set: {{ .runner_set_name }}
{{- end }}