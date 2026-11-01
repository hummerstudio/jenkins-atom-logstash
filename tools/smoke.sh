#!/usr/bin/env bash
# Build, then run every behaviour check against a fake syslog/Redis/Elasticsearch; optionally prove the checks bite.
#
#   ./tools/smoke.sh              # build + behaviour checks
#   ./tools/smoke.sh --mutations  # ... and the mutation run (rebuilds the atom per planted bug, slower)
set -uo pipefail
cd "$(dirname "$0")/.."

export JAVA_HOME="${JAVA_HOME:-/Users/tangming/tools/jdk-21.0.12.1+1/Contents/Home}"
export PATH="$JAVA_HOME/bin:$PATH"

./build.sh || { echo "build failed" >&2; exit 1; }
python3 tools/check.py || exit 1
if [ "${1:-}" = "--mutations" ]; then
  python3 tools/mutations.py || exit 1
fi
