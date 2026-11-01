#!/usr/bin/env bash
# Shared by tools/smoke.sh: run an atom the way the runner does, in a throwaway directory.
#
#   . "$(dirname "$0")/smoke-lib.sh"
#   run "$dir"        # needs dist/<atom>/<atom>.jar already built
#
# The runner puts the build environment into input.json and then layers the job's inputs on top; run() does the same,
# so ${BUILD_NUMBER} and friends expand inside an atom exactly as they do in Jenkins.
set -uo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# the atom's own name, not the directory's: a git worktree is called after its branch
ATOM_CODE="$(python3 -c "import json,sys;print(json.load(open(sys.argv[1]))['atomCode'])" "$repo/task.json" 2>/dev/null)"
if [ -z "$ATOM_CODE" ]; then
  ATOM_CODE="$(basename "$repo")"
  ATOM_CODE="${ATOM_CODE#jenkins-atom-}"
fi
JAR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../dist/$ATOM_CODE" && pwd)/$ATOM_CODE.jar"
JAVA_BIN="${JAVA_HOME:+$JAVA_HOME/bin/}java"

fail() { echo "smoke failed: $*" >&2; exit 1; }

# run <dir> [extra env as KEY=value ...]
run() {
  local dir="$1"
  shift || true
  python3 - "$dir" "$@" <<'PY'
import json, os, sys
directory, extra = sys.argv[1], sys.argv[2:]
path = os.path.join(directory, "input.json")
given = json.load(open(path, encoding="utf-8")) if os.path.getsize(path) else {}
data = {k: v for k, v in os.environ.items() if k.isupper() or k in ("atom_build_log",)}
data.update(given)
for pair in extra:
    key, _, value = pair.partition("=")
    data[key] = value
data.setdefault("atom_workspace", directory)
json.dump(data, open(path, "w", encoding="utf-8"))
PY
  ( cd "$dir" && env atom_data_dir="$dir" atom_data_input=input.json atom_data_output=output.json \
      atom_workspace="$dir" "$JAVA_BIN" -cp "$JAR" com.jenkinschina.atom.sdk.AtomRunner )
}

# output <dir> <jq-ish path> — reads output.json without jq
output() {
  python3 - "$1" "$2" <<'PY'
import json, sys
doc = json.load(open(f"{sys.argv[1]}/output.json", encoding="utf-8"))
node = doc.get("data", doc) if isinstance(doc, dict) else doc
for part in sys.argv[2].split("."):
    if isinstance(node, dict) and part in node:
        node = node[part]
    else:
        print(""); raise SystemExit
if isinstance(node, dict):
    print(node.get("value", ""))
else:
    print(node)
PY
}

# status <dir>
status() { python3 -c "import json,sys;print(json.load(open(sys.argv[1]+'/output.json')).get('status',''))" "$1"; }

# need_cmd <name> — skip the docker/node halves on machines that do not have them
need_cmd() { command -v "$1" >/dev/null 2>&1; }
