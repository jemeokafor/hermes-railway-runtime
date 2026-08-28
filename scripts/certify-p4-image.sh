#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  printf 'Usage: %s <image>\n' "${0##*/}" >&2
}

if [[ $# -ne 1 || -z "${1:-}" ]]; then
  usage
  exit 64
fi

report_path=${P4_REPORT_PATH:-"${PWD}/p4-image-certification.json"}
if [[ "${report_path}" != /* ]]; then
  report_path="${PWD}/${report_path}"
fi
report_parent=$(dirname -- "${report_path}")
report_name=$(basename -- "${report_path}")
if [[ -z "${report_name}" || "${report_name}" == "." || "${report_name}" == ".." || "${report_name}" == "/" ]]; then
  printf 'P4 report path is invalid: %s\n' "${report_path}" >&2
  exit 65
fi
mkdir -p -- "${report_parent}"
report_parent=$(CDPATH= cd -- "${report_parent}" && pwd -P)
report_path="${report_parent}/${report_name}"
# Remove prior evidence before any Docker preflight can fail.
if [[ -e "${report_path}" || -L "${report_path}" ]]; then
  rm -f -- "${report_path}"
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(CDPATH= cd -- "${script_dir}/.." && pwd)
harness_dir="${repo_root}/test/p4"
if [[ ! -f "${harness_dir}/p4_image_certification.py" ]]; then
  printf 'P4 harness is unavailable: %s\n' "${harness_dir}" >&2
  exit 66
fi

if ! command -v docker >/dev/null 2>&1; then
  printf 'P4 certification requires the Docker CLI.\n' >&2
  exit 69
fi
if ! docker info >/dev/null 2>&1; then
  printf 'P4 certification requires an available Docker daemon.\n' >&2
  exit 69
fi

image_reference=$1
if ! image_id=$(docker image inspect --format '{{.Id}}' "${image_reference}" 2>/dev/null); then
  printf 'Candidate image is unavailable: %s\n' "${image_reference}" >&2
  exit 66
fi
if [[ ! "${image_id}" =~ ^sha256:[0-9a-f]{64}$ ]]; then
  printf 'Candidate did not resolve to an immutable Docker image ID.\n' >&2
  exit 65
fi
source_commit=$(docker image inspect \
  --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' \
  "${image_id}")
if [[ ! "${source_commit}" =~ ^[0-9a-f]{40}$ || "${source_commit}" == 0000000000000000000000000000000000000000 ]]; then
  printf 'Candidate image has no non-unknown 40-hex source revision label.\n' >&2
  exit 65
fi

temporary_output=$(mktemp -d)
cleanup() {
  rm -rf -- "${temporary_output}"
}
trap cleanup EXIT

run_status=0
docker run --rm \
  --cgroupns private \
  --network none \
  --read-only \
  --security-opt no-new-privileges=true \
  --pids-limit 256 \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,size=256m,mode=1777 \
  --tmpfs /p4-work:rw,nosuid,nodev,size=2g,mode=0755 \
  --mount "type=bind,src=${harness_dir},dst=/p4,readonly" \
  --mount "type=bind,src=${temporary_output},dst=/p4-report" \
  --env "P4_IMAGE_ID=${image_id}" \
  --env "P4_IMAGE_REFERENCE=${image_reference}" \
  --env "P4_SOURCE_COMMIT=${source_commit}" \
  --env P4_NETWORK_MODE=none \
  --env "RAILWAY_GIT_COMMIT_SHA=${source_commit}" \
  --env "RAILWAY_IMAGE_DIGEST=${image_id}" \
  --env RAILWAY_DEPLOYMENT_ID= \
  --env MEDIA_EVIDENCE_MIN_FREE_BYTES=67108864 \
  --entrypoint /opt/hermes-venv/bin/python \
  "${image_id}" \
  -I /p4/p4_image_certification.py --report "/p4-report/${report_name}" || run_status=$?

candidate_report="${temporary_output}/${report_name}"
if [[ -f "${candidate_report}" ]]; then
  if ! command -v python3 >/dev/null 2>&1; then
    printf 'Host Python is required to validate the P4 certification report.\n' >&2
    run_status=70
  elif ! validated_status=$(python3 -I "${harness_dir}/p4_image_certification.py" --validate-report "${candidate_report}"); then
    printf 'Candidate produced a malformed P4 certification report; it was not retained.\n' >&2
    run_status=70
  elif [[ ( "${validated_status}" == "passed" && ${run_status} -eq 0 ) || ( "${validated_status}" == "failed" && ${run_status} -ne 0 ) ]]; then
    install -m 0644 "${candidate_report}" "${report_path}"
    printf 'P4 certification report: %s\n' "${report_path}"
  else
    printf 'Candidate report status contradicts the certification process exit; it was not retained.\n' >&2
    run_status=70
  fi
else
  printf 'Candidate exited without producing a P4 certification report.\n' >&2
  [[ ${run_status} -ne 0 ]] || run_status=70
fi

exit "${run_status}"
