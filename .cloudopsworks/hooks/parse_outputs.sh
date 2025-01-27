#!/bin/bash
set -e

echo "TF_PATH=${TG_CTX_TF_PATH} COMMAND=${TG_CTX_COMMAND} HOOK_NAME=${TG_CTX_HOOK_NAME}"
dotted_path=.$1
settings_path=$2
settings_yaml=${settings_path}/settings.yaml
tmpfile=$(mktemp)
tmpfile2=$(mktemp)
[ -f ${settings_yaml} ] || touch ${settings_yaml}
$TG_CTX_TF_PATH output -json | yq e "(to_entries | .[]) as \$i ireduce({}; ${dotted_path}.[\$i.key] = \$i.value.value)" > $tmpfile
yq eval-all -o=y '. as $item ireduce ({}; . *+ $item)' ${tmpfile} ${settings_yaml} > ${tmpfile2}
cp -f ${tmpfile2} ${settings_yaml}
rm $tmpfile $tmpfile2