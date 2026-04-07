#!/bin/bash
set -euo pipefail

SECRET_NAME=$1
SECRET_KEY=$2
SECRET_REGION=$3
STS_ROLE_ARN=$4
STS_ENDPOINT=$5

STS_JSON=$(aws sts assume-role --role-arn "$STS_ROLE_ARN" --role-session-name "get-secret-session" --endpoint-url "$STS_ENDPOINT" --region "$SECRET_REGION")
export AWS_ACCESS_KEY_ID=$(echo "$STS_JSON" | jq -r '.Credentials.AccessKeyId')
export AWS_SECRET_ACCESS_KEY=$(echo "$STS_JSON" | jq -r '.Credentials.SecretAccessKey')
export AWS_SESSION_TOKEN=$(echo "$STS_JSON" | jq -r '.Credentials.SessionToken')

#aws sts get-caller-identity

SECRET_VALUE=$(aws secretsmanager get-secret-value --secret-id "$SECRET_NAME" --region "$SECRET_REGION" --query SecretString --output text)

SECRET_DATA=$(echo "$SECRET_VALUE" | jq -r ".$SECRET_KEY")

echo $SECRET_DATA