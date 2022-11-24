#!/bin/bash

RUNNING_FILE=/tmp/mender-client-$$.run
KEYS_DIR=${KEYS_DIR:-"./keys"}
MENDER_SERVER_URL=${MENDER_SERVER_URL:-"https://hosted.mender.io"}
MENDER_TENANT_TOKEN=${MENDER_TENANT_TOKEN}

hexchars="0123456789ABCDEF"
end=$( for i in {1..6} ; do echo -n ${hexchars:$(( $RANDOM % 16 )):1} ; done | sed -e 's/\(..\)/:\1/g' )
MENDER_DEVICE_MAC_ADDRESS=${DEVICE_MAC_ADDRESS:-"00:11:22${end}"}
RATE_LIMIT_SLEEP_INTERVAL=${RATE_LIMIT_SLEEP_INTERVAL:-"10"}

CURL_OPTIONS=""

MENDER_DEVICE_TYPE=${MENDER_DEVICE_TYPE:-"raspberrypi4"}

# This variable is mutable
MENDER_ARTIFACT_NAME=${MENDER_ARTIFACT_NAME:-"release-v1"}

function show_help() {
  cat << EOF
mender-client.sh

This is simple Mender client written in bash and was primarily developed to
demonstrate the device facing API of the Mender server and what the bare
minimum is to implement a custom Mender client, e.g in a MCU.

The following workflows are covered (in the order they are performed):

    1. device authorization
    2. pushing inventory
    3. checking for deployments
    4. downloading deplyoment
    5. updating deployment status on the server

Usage: ./$0 COMMAND [options]

Options:
  -t, --token                 - Mender server tenant token
  -d, --device-type           - Device type string to report to the server
  -s, --server-url            - Mender server URL
  -k, --keys-dir              - Client's keys directory
  -m, --mac-address           - Client's MAC address
  -r, --rate-limit            - Rate limit (sleep interval)
  -a, --artifact-name         - Artifact name
  --debug                     - Enables debug mode

EOF
}

function show_help_keys() {
  cat << EOF
You need to generate a key-pair to be able to authorize the "device".

You can generate a key-pair using the following commands:

    mkdir keys
    openssl genpkey -algorithm RSA -out keys/private.key -pkeyopt rsa_keygen_bits:3072
    openssl rsa -in keys/private.key -out keys/private.key
    openssl rsa -in keys/private.key -out keys/public.key -pubout

EOF
}

function log() {
  echo -n "[$(date +%T.%N)] "
  echo -e $1
}

function check_input() {
    [[ -z "$MENDER_SERVER_URL" || "$MENDER_SERVER_URL" == "" ]] && { log "WARN: MENDER_SERVER_URL is not set, using default '$MENDER_SERVER_URL'"; }
    [[ -z "$KEYS_DIR" || "$KEYS_DIR" == "" ]] && { log "WARN: KEYS_DIR is not set, using default '$KEYS_DIR'"; }
    [[ -z "${MENDER_TENANT_TOKEN}" || -z "${MENDER_TENANT_TOKEN}" ]] && { show_help; exit 1; }
    [[ ! -e "${KEYS_DIR}"/private.key || ! -e "${KEYS_DIR}"/public.key ]] && { show_help_keys; exit 1; }
    if [ "$DEBUG" == "1" ]; then
      CURL_OPTIONS=" -vvvv "
      set -x
    fi
}

function normalize_data() {
    echo "$1" | tr -d '\n' | tr -d '\r'
}

function generate_signature() {
  # Request signature, computed as 'BASE64(SIGN(device_private_key, SHA256(request_body)))'.
  #
  # It is very important to clean up any newlines (\r or \n) in the request body
  # here as this will be removed when the request is made and if they are not
  # cleaned up the signature will invalid
  normalize_data "$(cat auth.json)" | \
    openssl dgst -sha256 -sign "${KEYS_DIR}"/private.key | openssl base64 -A
}

function auth_request_status() {
  x_men_signature=$(generate_signature)
  curl ${CURL_OPTIONS} -k -s -o /dev/null -w '%{http_code}' \
    -H "Content-Type: application/json" \
    -H "X-MEN-Signature: ${x_men_signature}" \
    --data "@auth.json" \
    ${MENDER_SERVER_URL}/api/devices/v1/authentication/auth_requests
}

# $1 - path to data JSON file for auth request
function wait_for_authorized() {
  log "Prepare authorization request"
  # Replace newlines with \n
  pubkey=$(awk 'NF {sub(/\r/, ""); printf "%s\\n",$0;}' "${KEYS_DIR}"/public.key)

  # Prepare authorization request
  cat <<- EOF > auth.json
{
    "id_data": "{ \"mac\": \"${MENDER_DEVICE_MAC_ADDRESS}\"}",
    "pubkey": "${pubkey}",
    "tenant_token": "${MENDER_TENANT_TOKEN}"
}
EOF

  log "Send authorization request for '$MENDER_DEVICE_MAC_ADDRESS'"
  while [ -f "$RUNNING_FILE" ]; do
    status_code=$(auth_request_status)
    if [ "$status_code" == "200" ]; then
        log "Client has been authorized"
      break;
    fi
    echo -n "."
    sleep 5
  done
}

function get_jwt() {
  x_men_signature=$(generate_signature)
  curl ${CURL_OPTIONS} -s -k \
    -H "Content-Type: application/json" \
    -H "X-MEN-Signature: ${x_men_signature}" \
    --data "@auth.json" \
    ${MENDER_SERVER_URL}/api/devices/v1/authentication/auth_requests
}

function send_inventory() {
  [[ -z "$MENDER_ARTIFACT_NAME" ]] && { log "ERROR: MENDER_ARTIFACT_NAME is empty"; exit 1; }
  log "Send inventory data..."
  cat <<- EOF > inventory.json
[
    {
      "name":"device_type",
      "value":"${MENDER_DEVICE_TYPE}"
    },
    {
      "name":"artifact_name",
      "value":"${MENDER_ARTIFACT_NAME}"
    },
    {
      "name":"kernel",
      "value":"$(uname -a)"
    }
]
EOF

  curl ${CURL_OPTIONS} -k \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $JWT" \
    --data "@inventory.json" \
    -X PATCH \
    ${MENDER_SERVER_URL}/api/devices/v1/inventory/device/attributes
}

function deployments_status() {
  [[ -z "$MENDER_ARTIFACT_NAME" || "$MENDER_ARTIFACT_NAME" == "" ]] && { log "ERROR: MENDER_ARTIFACT_NAME is empty"; exit 1; }
  curl ${CURL_OPTIONS} -k -s -o /dev/null -w '%{http_code}' \
    -H "Authorization: Bearer $JWT" \
    -X GET \
    "${MENDER_SERVER_URL}/api/devices/v1/deployments/device/deployments/next?artifact_name=${MENDER_ARTIFACT_NAME}&device_type=${MENDER_DEVICE_TYPE}"
}

function check_deployment() {
  log "Checking for deployments with artifact '$MENDER_ARTIFACT_NAME'"
  while [ -f "$RUNNING_FILE" ]; do
    status_code=$(deployments_status)
    if [ "$status_code" == "200" ]; then
      echo ""
      log "There is a deployments waiting for us"
      break;
    elif [ "$status_code" == "401" ]; then
      log "JWT token expired, obtain a new one"
      JWT=$(get_jwt)
    fi
    echo -n "."
    sleep 5
  done
}

function get_deplyoment() {
  [[ -z "$MENDER_ARTIFACT_NAME" || "$MENDER_ARTIFACT_NAME" == "" ]] && { log "ERROR: MENDER_ARTIFACT_NAME is empty"; exit 1; }
  curl ${CURL_OPTIONS} -s -k \
    -H "Authorization: Bearer $JWT" \
    -X GET \
    "${MENDER_SERVER_URL}/api/devices/v1/deployments/device/deployments/next?artifact_name=${MENDER_ARTIFACT_NAME}&device_type=${MENDER_DEVICE_TYPE}"
}

# $1 - deployment id
# $2 - enum (installing, downloading, rebooting, success, failure, already-installed)
function set_deplyoment_status() {
  [[ -z "$1" ]] && { log "ERROR: \$1 (deployment id) is empty"; exit 1; }
  [[ -z "$2" ]] && { log "ERROR: \$2 (status) is empty"; exit 1; }
  log "Deployment '${1}': state changed to '${2}'"
  curl ${CURL_OPTIONS} -k \
    -H "Authorization: Bearer $JWT" \
    -H "Content-Type: application/json" \
    -d "{\"status\":\"${2}\"}" \
    -X PUT \
    "${MENDER_SERVER_URL}/api/devices/v1/deployments/device/deployments/${1}/status"
}

function download_artifact() {
  set_deplyoment_status "${deployment_id}" "downloading"

  log "Downloading artifact: ${deployment_url}"
  # Here one would decompress the artifact and write it to the storage medium
  set -e
  curl -s -k -o /dev/null ${deployment_url}
  log "Artifact downloading is done"
  set +e
}


while (( "$#" )); do
  case "$1" in
    -t | --token)
      MENDER_TENANT_TOKEN="${2}"
      shift 2
      ;;
    -d | --device-type)
      MENDER_DEVICE_TYPE="${2}"
      shift 2
      ;;
    -s | --server-url)
      MENDER_SERVER_URL="${2}"
      shift 2
      ;;
    -k | --keys-dir)
      KEYS_DIR="${2}"
      shift 2
      ;;
    -m | --mac-address)
      MENDER_DEVICE_MAC_ADDRESS="${2}"
      shift 2
      ;;
    -r | --rate-limit)
      RATE_LIMIT_SLEEP_INTERVAL="${2}"
      shift 2
      ;;
    -a | --artifact-name)
      MENDER_ARTIFACT_NAME="${2}"
      shift 2
      ;;
    --debug)
      DEBUG=1
      shift 1
      ;;
    *)
      show_help
      exit 1
      ;;
  esac
done

check_input


# Main logic execution
[ -f "$RUNNING_FILE" ] && exit 2

echo $$ > "$RUNNING_FILE";
log "Starting... 'rm -f $RUNNING_FILE' to quit"


# Send auth request and wait while authorized
wait_for_authorized

# Once we are are authorized with the server we can download a time limited
# JSON Web Token which we will be used for all subsequent API calls.
log "Fetch JSON Web Token"
JWT=$(get_jwt)

# Send inventory data
send_inventory

while [ -f "$RUNNING_FILE" ]; do
  check_deployment

  # sleep $RATE_LIMIT_SLEEP_INTERVAL seconds to avoid being rate limited (429)
  sleep ${RATE_LIMIT_SLEEP_INTERVAL}

  # Handle deployment
  log "Getting deployment"
  deployment_json=$(get_deplyoment)
  [[ -z "$deployment_json" || "$deployment_json" == "" ]] && { log "ERROR: failed to get deployment"; exit 1; }
  deployment_id=$(jq -r '.id' <<< ${deployment_json})
  deployment_url=$(jq -r '.artifact.source.uri' <<< ${deployment_json})
  [[ -z "$deployment_id" || "$deployment_id" == "" ]] && { log "ERROR: \$deployment_id is empty"; exit 1; }
  [[ -z "$deployment_url" || "$deployment_url" == "" ]] && { log "ERROR: \$deployment_url is empty"; exit 1; }

  download_artifact

  # Here one would prepare the bootloader flags prior to restarting and try
  # booting the new image
  set_deplyoment_status "${deployment_id}" "installing"
  sleep 10

  # Reboot device :)
  set_deplyoment_status "${deployment_id}" "rebooting"
  sleep 10

  # Here one would do a sanity check if the update was successful, e.g the
  # minimum success criteria could be that the device boots and is able to
  # re-connect to the Mender server

  # Marking the update complete, optionally one could trigger a roll-back here
  # and later on report status "failure"
  set_deplyoment_status "${deployment_id}" "success"

  # Update artifact name
  MENDER_ARTIFACT_NAME=$(jq -r '.artifact.artifact_name' <<< ${deployment_json})
  [[ -z "$MENDER_ARTIFACT_NAME" || "$MENDER_ARTIFACT_NAME" == "" ]] && { log "ERROR: MENDER_ARTIFACT_NAME is empty"; exit 1; }

  # Push inventory so that artifact_name change is reflected on the server
  send_inventory
done
