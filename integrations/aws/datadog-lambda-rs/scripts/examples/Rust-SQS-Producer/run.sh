#!/usr/bin/env bash
# Rust-SQS-Producer example: Rust producer → SQS → Python consumer
#
# Usage:
#   ./run.sh build
#   ./run.sh deploy --role-arn <arn> [options]
#   ./run.sh update [options]
#   ./run.sh invoke [options] [-- <payload>]
#
# Required:
#   DD_API_KEY env var must be set for deploy.
#
# Flags:
#   --role-arn ARN          IAM role ARN for Lambda functions (required for deploy)
#   --region REGION         AWS region (default: us-east-1)
#   --queue QUEUE           SQS queue name (default: rust-to-python-queue)
#   --producer NAME         Rust producer function name (default: rust-sqs-producer)
#   --consumer NAME         Python consumer function name (default: python-sqs-consumer)
#   --ext-version VER       Datadog Extension layer version (default: 92)
#   --python-version VER    Datadog Python layer version (default: 122)
#
# Note: This POC targets ARM (aarch64) only. Build requires cargo-zigbuild.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/../../.." && pwd)"

# --- Defaults ---
REGION="us-east-1"
QUEUE="rust-to-python-queue"
PRODUCER="rust-sqs-producer"
CONSUMER="python-sqs-consumer"
EXT_VER="92"
PY_VER="122"
ROLE_ARN=""

TARGET="aarch64-unknown-linux-gnu"
EXAMPLE="rust_sqs_producer"

# --- Parse flags ---
CMD="${1:-}"
shift || true

while [[ $# -gt 0 ]]; do
  case "$1" in
    --role-arn)     ROLE_ARN="$2"; shift 2 ;;
    --region)       REGION="$2"; shift 2 ;;
    --queue)        QUEUE="$2"; shift 2 ;;
    --producer)     PRODUCER="$2"; shift 2 ;;
    --consumer)     CONSUMER="$2"; shift 2 ;;
    --ext-version)  EXT_VER="$2"; shift 2 ;;
    --python-version) PY_VER="$2"; shift 2 ;;
    --)             shift; break ;;
    *)              break ;;
  esac
done

DD_EXT_LAYER="arn:aws:lambda:${REGION}:464622532012:layer:Datadog-Extension-ARM:${EXT_VER}"
DD_PY_LAYER="arn:aws:lambda:${REGION}:464622532012:layer:Datadog-Python312-ARM:${PY_VER}"
ZIP="${PROJECT_DIR}/target/bootstrap.zip"

# ------------------------------------------------------------------ build
cmd_build() {
  echo ">> Building example '${EXAMPLE}' for ${TARGET} (release)..."
  cargo zigbuild \
    --manifest-path "${PROJECT_DIR}/Cargo.toml" \
    --example "${EXAMPLE}" \
    --release \
    --target "${TARGET}"

  local bin="${PROJECT_DIR}/target/${TARGET}/release/examples/${EXAMPLE}"
  echo ">> Packaging bootstrap zip..."
  cp "${bin}" "${PROJECT_DIR}/target/bootstrap"
  (cd "${PROJECT_DIR}/target" && zip -j bootstrap.zip bootstrap && rm bootstrap)
  echo ">> Done: ${ZIP}"
}

# ----------------------------------------------------------------- deploy
cmd_deploy() {
  : "${DD_API_KEY:?Set DD_API_KEY}"
  [[ -n "${ROLE_ARN}" ]] || { echo ">> --role-arn is required for deploy"; exit 1; }
  [ -f "${ZIP}" ] || { echo ">> bootstrap.zip not found — run '$0 build' first"; exit 1; }

  # Create SQS queue
  echo ">> Creating SQS queue '${QUEUE}'..."
  local queue_url
  queue_url=$(aws sqs create-queue \
    --queue-name "${QUEUE}" --region "${REGION}" \
    --query 'QueueUrl' --output text)

  local queue_arn
  queue_arn=$(aws sqs get-queue-attributes \
    --queue-url "${queue_url}" --attribute-names QueueArn --region "${REGION}" \
    --query 'Attributes.QueueArn' --output text)

  echo ">> Queue URL: ${queue_url}"
  echo ">> Queue ARN: ${queue_arn}"

  # Deploy Rust producer
  echo ">> Creating Rust producer '${PRODUCER}'..."
  aws lambda create-function \
    --function-name "${PRODUCER}" \
    --runtime provided.al2023 --architectures arm64 --handler bootstrap \
    --role "${ROLE_ARN}" \
    --zip-file "fileb://${ZIP}" \
    --timeout 30 --memory-size 256 --region "${REGION}" \
    --layers "${DD_EXT_LAYER}" \
    --environment "$(cat <<EOF
{"Variables":{"DD_API_KEY":"${DD_API_KEY}","DD_TRACE_ENABLED":"true","DD_SERVICE":"${PRODUCER}","DD_ENV":"dev","QUEUE_URL":"${queue_url}"}}
EOF
)"

  # Package and deploy Python consumer
  echo ">> Packaging Python consumer..."
  local python_zip="/tmp/python-sqs-consumer.zip"
  (cd "${SCRIPT_DIR}/python-sqs-consumer" && zip -j "${python_zip}" handler.py)

  echo ">> Creating Python consumer '${CONSUMER}'..."
  aws lambda create-function \
    --function-name "${CONSUMER}" \
    --runtime python3.12 --architectures arm64 \
    --handler datadog_lambda.handler.handler \
    --role "${ROLE_ARN}" \
    --zip-file "fileb://${python_zip}" \
    --timeout 30 --memory-size 256 --region "${REGION}" \
    --layers "${DD_PY_LAYER}" "${DD_EXT_LAYER}" \
    --environment "$(cat <<EOF
{"Variables":{"DD_API_KEY":"${DD_API_KEY}","DD_TRACE_ENABLED":"true","DD_SERVICE":"${CONSUMER}","DD_ENV":"dev","DD_LAMBDA_HANDLER":"handler.handler"}}
EOF
)"

  # Wire SQS trigger for Python consumer
  echo ">> Creating SQS trigger: ${QUEUE} -> ${CONSUMER}..."
  aws lambda create-event-source-mapping \
    --function-name "${CONSUMER}" \
    --event-source-arn "${queue_arn}" \
    --batch-size 10 --region "${REGION}"

  echo ">> Done! Invoke '${PRODUCER}' to send a message -> '${QUEUE}' -> '${CONSUMER}'."
}

# ----------------------------------------------------------------- update
cmd_update() {
  [ -f "${ZIP}" ] || { echo ">> bootstrap.zip not found — run '$0 build' first"; exit 1; }

  echo ">> Updating Rust producer '${PRODUCER}'..."
  aws lambda update-function-code \
    --function-name "${PRODUCER}" --zip-file "fileb://${ZIP}" --region "${REGION}"

  echo ">> Packaging Python consumer..."
  local python_zip="/tmp/python-sqs-consumer.zip"
  (cd "${SCRIPT_DIR}/python-sqs-consumer" && zip -j "${python_zip}" handler.py)

  echo ">> Updating Python consumer '${CONSUMER}'..."
  aws lambda update-function-code \
    --function-name "${CONSUMER}" --zip-file "fileb://${python_zip}" --region "${REGION}"

  echo ">> Updated both functions."
}

# ----------------------------------------------------------------- invoke
cmd_invoke() {
  local payload="${1:-{\"body\": \"hello from Rust SQS producer\"}}"
  local out="/tmp/${PRODUCER}-response.json"

  echo ">> Invoking '${PRODUCER}'..."
  echo ">> Payload: ${payload}"
  aws lambda invoke \
    --function-name "${PRODUCER}" \
    --payload "${payload}" \
    --cli-binary-format raw-in-base64-out \
    --region "${REGION}" "${out}"

  echo ">> Response:"
  cat "${out}"
  echo ""
}

# ------------------------------------------------------------------- main
case "${CMD}" in
  build)  cmd_build  ;;
  deploy) cmd_deploy ;;
  update) cmd_update ;;
  invoke) cmd_invoke "$@" ;;
  *)
    echo "Usage: $0 {build|deploy|update|invoke} [flags]"
    echo ""
    echo "  build   Build the Rust producer binary for aarch64"
    echo "  deploy  Create queue, deploy both Lambdas, wire SQS trigger"
    echo "  update  Update both Lambdas' code"
    echo "  invoke  Invoke the Rust producer (pass payload after --)"
    echo ""
    echo "Flags:"
    echo "  --role-arn ARN          IAM role ARN (required for deploy)"
    echo "  --region REGION         AWS region (default: us-east-1)"
    echo "  --queue NAME            SQS queue name"
    echo "  --producer NAME         Producer function name"
    echo "  --consumer NAME         Consumer function name"
    echo "  --ext-version VER       Datadog Extension layer version"
    echo "  --python-version VER    Datadog Python layer version"
    exit 1
    ;;
esac
