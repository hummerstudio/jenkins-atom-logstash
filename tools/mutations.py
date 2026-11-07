#!/usr/bin/env python3
"""Plant one bug at a time in the atom and prove the checks catch it.

A green suite means nothing if it stays green for a broken atom. Each mutation is one textual change to the real
source; the mutated tree is rebuilt and the named check must fail. A survivor is a hole in the suite.

    python3 tools/mutations.py
"""
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent.parent
CODE = "logstash"
SOURCE = HERE / "src" / "main" / "java" / "com" / "jenkinschina" / "atom" / "logstash" / "LogstashAtom.java"

MUTATIONS = [
    ("the CEE prefix loses its leading space",
     'static final String CEE_PREFIX = " @cee: ";', 'static final String CEE_PREFIX = "@cee: ";',
     "payload.syslog"),
    ("the syslog app name loses the colon SyslogDao sets",
     'static final String APP_NAME = "jenkins:";', 'static final String APP_NAME = "jenkins";',
     "payload.syslog"),
    ("the syslog PRI comes from the wrong facility",
     'static final int FACILITY_USER = 1;', 'static final int FACILITY_USER = 2;', "syslog.rfc5424"),
    ("the RFC 3164 header timestamp is written in UTC",
     'sb.append(RFC3164_TIMESTAMP.format(stamp)).append(\' \');',
     'sb.append(RFC3164_TIMESTAMP.format(stamp.withZoneSameInstant(java.time.ZoneOffset.UTC))).append(\' \');',
     "syslog.timezone"),
    ("the RFC 5424 header drops its version digit",
     "sb.append('1').append(' ');", "sb.append(' ');", "syslog.rfc5424"),
    ("the RFC 5424 timestamp is local time instead of GMT",
     '.withZone(java.time.ZoneOffset.UTC);', '.withZone(java.time.ZoneId.systemDefault());', "syslog.rfc5424"),
    ("the legacy seconds timestamp format is ignored",
     "DateTimeFormatter timestampFormat = millis ? TIMESTAMP_MILLIS : TIMESTAMP_SECONDS;",
     "DateTimeFormatter timestampFormat = TIMESTAMP_MILLIS;", "legacy.seconds"),
    ("source_host is sent even when the root URL is empty",
     'if (!jenkinsUrl.isEmpty()) {', 'if (true) {', "nulls.and.types"),
    ("@version is a string instead of the integer 1",
     'payload.put("@version", 1);', 'payload.put("@version", "1");', "payload.syslog"),
    ("buildDuration is written in seconds, not milliseconds",
     'data.put("buildDuration", duration > 0 ? duration : Math.max(0L, System.currentTimeMillis() - buildMs));',
     'data.put("buildDuration", (duration > 0 ? duration : Math.max(0L, System.currentTimeMillis() - buildMs)) / 1000);',
     "payload.syslog"),
    ("passCount forgets the skipped tests",
     'tests.put("passCount", total - skipped - failed);', 'tests.put("passCount", total - failed);', "payload.tests"),
    ("the message is sent whole instead of the last maxLines lines",
     'return new ArrayList<>(lines.subList(lines.size() - maxLines, lines.size()));', 'return lines;',
     "maxlines.tail"),
    ("maxLines=0 sends everything instead of nothing",
     'if (maxLines < 0 || lines.size() <= maxLines) {', 'if (maxLines <= 0 || lines.size() <= maxLines) {',
     "maxlines.zero"),
    ("Redis skips AUTH when a password is set",
     'if (!password.isEmpty()) {\n                command(out, "AUTH", password);',
     'if (false) {\n                command(out, "AUTH", password);', "redis.auth.and.rpush"),
    ("Redis pushes to the head of the list (LPUSH)",
     'command(out, "RPUSH", key, json);', 'command(out, "LPUSH", key, json);', "redis.auth.and.rpush"),
    ("Redis accepts a zero-length push",
     'if (length <= 0) {', 'if (length < 0) {', "redis.zero.length"),
    ("Elasticsearch gets text/plain instead of the JSON content type",
     'static final String ES_CONTENT_TYPE = "application/json; charset=UTF-8";',
     'static final String ES_CONTENT_TYPE = "text/plain";', "es.post"),
    ("Elasticsearch treats a non-2xx answer as success",
     'if (status < 200 || status >= 300) {', 'if (false) {', "es.error"),
    ("Elasticsearch drops the Basic Authorization header",
     'request.header("Authorization", "Basic " + token);', 'request.header("X-Noop", "Basic " + token);',
     "es.post"),
    ("failOnError=false is ignored",
     'if (!failOnError) {', 'if (false) {', "failonerror.false"),
    ("a dry run sends anyway",
     'if (dryRun) {', 'if (false) {', "dryrun.sends.nothing"),
    ("an unfinished build still carries a result field",
     'if (!result.isEmpty() && !result.contains("${")) {', 'if (true) {', "nulls.and.types"),
    ("testResults is written even without any test action",
     'if (expand(context, context.getParam("testsTotal", "")).trim().isEmpty()) {\n            return tests;\n        }',
     'if (false) {\n            return tests;\n        }', "nulls.and.types"),
    ("the transient timestamp leaks into the data object",
     'data.put("buildVariables", variables(context));',
     'data.put("timestamp", format.format(Instant.ofEpochMilli(buildMs)));\n        '
     'data.put("buildVariables", variables(context));', "nulls.and.types"),
]


def sdk_jar():
    env = os.environ.get("SDK_JAR")
    if env:
        return env
    # CI checks the SDK out inside the workspace (jenkins-atom-sdk/), a local tree has it next door
    for root in (HERE.parent / "jenkins-atom-sdk", HERE / "jenkins-atom-sdk"):
        candidates = sorted((root / "target").glob("jenkins-atom-sdk-*.jar"))
        if candidates:
            return str(candidates[-1])
    raise SystemExit("build the SDK first: cd ../jenkins-atom-sdk && mvn -DskipTests package")


def build(tree):
    env = dict(os.environ)
    env["SDK_JAR"] = sdk_jar()
    proc = subprocess.run(["mvn", "-q", "-B", "-ntp", "-DskipTests", "package"], cwd=tree, env=env, capture_output=True, text=True)
    if proc.returncode != 0:
        return None, proc.stderr[-1500:]
    return tree / "target" / "dist" / CODE / (CODE + ".jar"), proc.stdout


def main():
    failures = 0
    for index, (name, old, new, case) in enumerate(MUTATIONS, 1):
        tree = pathlib.Path(tempfile.mkdtemp(prefix=CODE + "-mut-")) / "atom"
        shutil.copytree(HERE, tree, ignore=shutil.ignore_patterns("dist", "target", ".git", "__pycache__"))
        source = tree / SOURCE.relative_to(HERE)
        text = source.read_text()
        if old not in text:
            print("SKIP  %s: the mutation no longer matches the source" % name)
            failures += 1
            continue
        source.write_text(text.replace(old, new, 1))
        jar, output = build(tree)
        if jar is None:
            print("SKIP  %s: the mutated atom does not build: %s" % (name, output))
            failures += 1
            continue
        proc = subprocess.run([sys.executable, "tools/check.py", case, "--jar", str(jar)],
                              cwd=tree, capture_output=True, text=True)
        if proc.returncode == 0:
            print("SURVIVED %-2d %s (case %s stayed green)" % (index, name, case))
            failures += 1
        else:
            print("caught   %-2d %s" % (index, name))
    print("\n%d/%d mutations caught" % (len(MUTATIONS) - failures, len(MUTATIONS)))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
