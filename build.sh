#!/usr/bin/env bash
# Build the atom with Maven. Kept as a wrapper because tools/smoke.sh, the READMEs and the centre's installer all call
# ./build.sh; the build definition itself is pom.xml (parent: com.jenkinschina.atoms:atoms-parent).
#
#   ./build.sh                      # mvn package -> target/<code>.jar and dist/<code>/
#   ATOM_JAR=... ./build.sh         # already built by the Maven execution that called us: nothing to do
set -euo pipefail
cd "$(dirname "$0")"

code="$(python3 -c 'import json,sys; print(json.load(open("task.json"))["atomCode"])')"

# `mvn verify` runs tools/smoke.sh, which calls this script: packing again from inside the run would fight the build
# that is already in flight, and the jar it needs is the one the exec plugin passed in.
if [ -n "${ATOM_JAR:-}" ] && [ -f "${ATOM_JAR}" ]; then
  echo "built dist/$code: (from the Maven run)"
  exit 0
fi

if [ -n "${MAVEN_HOME:-}" ] && [ -x "$MAVEN_HOME/bin/mvn" ]; then
  MVN="$MAVEN_HOME/bin/mvn"
else
  MVN=mvn
fi

"$MVN" -q -ntp -DskipTests package
echo "built dist/$code: $(ls dist/$code 2>/dev/null | tr '\n' ' ')"
