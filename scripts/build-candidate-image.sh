#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
candidate_image=${CANDIDATE_IMAGE:-hermes-railway-runtime:candidate}
minimum_free_bytes=${DOCKER_MIN_FREE_BYTES:-7516192768}
source_sha=${SOURCE_SHA:-$(git -C "${repo_root}" rev-parse HEAD)}

die() {
  printf '%s\n' "$*" >&2
  exit 1
}

available_bytes() {
  python3 -c 'import os, sys; stat = os.statvfs(sys.argv[1]); print(stat.f_bavail * stat.f_frsize)' "${repo_root}"
}

require_space() {
  local available
  available=$(available_bytes)
  if (( available < minimum_free_bytes )); then
    printf 'Docker disk floor reached: %s bytes free, need at least %s.\n' "${available}" "${minimum_free_bytes}" >&2
    return 1
  fi
}

[[ "${source_sha}" =~ ^[0-9a-f]{40}$ ]] || die "SOURCE_SHA must be a 40-character lowercase Git SHA."
(( minimum_free_bytes >= 6000000000 )) || die "DOCKER_MIN_FREE_BYTES must retain at least 6 GB."
git -C "${repo_root}" diff --quiet || die "Refusing Docker build from a dirty worktree."
git -C "${repo_root}" diff --cached --quiet || die "Refusing Docker build from a dirty index."

docker builder prune --all --force
require_space || die "Refusing Docker build before it starts."

build_pid=''
trap '[[ -z "${build_pid}" ]] || kill "${build_pid}" 2>/dev/null || true; exit 130' INT TERM

docker build \
  --build-arg "RAILWAY_GIT_COMMIT_SHA=${source_sha}" \
  --tag "${candidate_image}" \
  "${repo_root}" &
build_pid=$!

while kill -0 "${build_pid}" 2>/dev/null; do
  if ! require_space; then
    kill "${build_pid}" 2>/dev/null || true
    wait "${build_pid}" || true
    build_pid=''
    docker builder prune --all --force
    exit 1
  fi
  sleep 1
done

wait "${build_pid}"
build_pid=''
docker builder prune --all --force
if ! require_space; then
  docker image rm "${candidate_image}" >/dev/null 2>&1 || true
  die "Candidate image removed because the host-disk floor was not retained."
fi
