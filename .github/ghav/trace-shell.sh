#!/usr/bin/env bash
# GHAV tracing shell: runs one GitHub Actions `run` step under strace.
# Used as `shell: bash <this file> {0}`. strace runs as root (so setuid
# programs such as sudo keep working) and the step itself runs as `runner`.
set -u
script="$1"
root="${GHAV_TRACE_DIR:-$HOME/ghav-trace}"
dir="$root/${GHAV_STEP:-${GITHUB_ACTION:-step}}"
mkdir -p "$dir"
printf '%s\n' "$PWD" > "$dir/cwd"
date +%s.%N > "$dir/start"
opts=(-f -ff -qq -ttt -y -s 4096 -e trace=%file,%process,getdents64,getdents,fchdir -o "$dir/t")
# No --seccomp-bpf: combined with -u it fails with ENOSYS on exec, and it would
# set no_new_privs, which breaks sudo inside traced steps.
exec sudo -E env "PATH=$PATH" strace -u "$(id -un)" "${opts[@]}" \
  bash --noprofile --norc -eo pipefail "$script"
