#!/usr/bin/env bash
# Thin wrapper so the common case is `./run.sh <pattern>` on any platform.
#
# Everything lives in run.py; this exists only so the command is short and
# memorable. See `./run.sh --help`.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "${PYTHON:-python3}" "$here/run.py" "$@"
