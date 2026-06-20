#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 The PharosVPN Authors
#
# Build the dashboard + cox, then run the controller — the one-shot dev loop.
#
#   scripts/dev.sh [options] [-- <extra args passed to `cox serve`>]
#
# Options:
#   --no-ui        skip the dashboard build (reuse the embedded dist as-is)
#   --build-only   build, but don't run
#   -h, --help     show this help
#
# Env:
#   CONFIG   config file passed to `cox serve` (default: cox.yaml)
#   BIN      output binary path (default: bin/cox)
#
# Examples:
#   scripts/dev.sh                       # build everything, run `cox serve`
#   scripts/dev.sh --no-ui               # skip the (slow) UI build, run
#   CONFIG=prod.yaml scripts/dev.sh      # run with a different config
#   scripts/dev.sh -- --help             # forward flags to `cox serve`
set -euo pipefail
cd "$(dirname "$0")/.."

CONFIG="${CONFIG:-cox.yaml}"
BIN="${BIN:-bin/cox}"
BUILD_UI=1
RUN=1
serve_args=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-ui)     BUILD_UI=0; shift ;;
    --build-only) RUN=0; shift ;;
    -h|--help)   sed -n '5,22p' "$0"; exit 0 ;;
    --)          shift; serve_args+=("$@"); break ;;
    *)           serve_args+=("$1"); shift ;;
  esac
done

# 1. Dashboard → internal/webui/dist (Go embeds this into the binary).
if [[ "$BUILD_UI" == 1 ]]; then
  echo "==> building dashboard (web → internal/webui/dist)"
  # fnm isn't loaded in non-interactive shells, so npm may not be on PATH yet.
  if command -v fnm >/dev/null 2>&1; then eval "$(fnm env)"; fi
  if ! command -v npm >/dev/null 2>&1; then
    echo "!! npm not found — install Node (or run with --no-ui)" >&2
    exit 1
  fi
  [[ -d web/node_modules ]] || ( cd web && npm install )
  ( cd web && npm run build )
else
  echo "==> skipping dashboard build (--no-ui); using the existing embedded dist"
fi

# 2. cox — fully static, version-stamped single binary (reuses scripts/build.sh).
echo "==> building cox → $BIN"
scripts/build.sh "$BIN"

# 3. Run the controller (exec so Ctrl-C / signals reach cox directly).
# ${arr[@]+"${arr[@]}"} expands to nothing when the array is empty — the portable
# way to pass an optional arg list under `set -u` (macOS still ships bash 3.2).
if [[ "$RUN" == 1 ]]; then
  echo "==> running: $BIN serve --config $CONFIG ${serve_args[*]+${serve_args[*]}}"
  exec "$BIN" serve --config "$CONFIG" ${serve_args[@]+"${serve_args[@]}"}
fi
echo "==> built (not running; --build-only)"
