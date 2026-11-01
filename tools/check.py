#!/usr/bin/env python3
"""Behaviour checks for the logstash atom.

Every check drives the atom the way the runner does (input.json in, output.json out) against a fake indexer that
records the raw bytes, and then recomputes from its own inputs what the logstash plugin would have put on the wire:
the payload object (AbstractLogstashIndexerDao#buildPayload over a Gson-serialised BuildData), the syslog frame
(SyslogDao + SyslogMessage RFC 3164 / RFC 5424), the RESP command sequence (RedisDao) and the HTTP request
(ElasticSearchDao). Nothing here reads the atom's own output to decide what was expected.

    python3 tools/check.py                    # every check
    python3 tools/check.py payload            # only checks whose name contains "payload"
    python3 tools/check.py payload --jar X    # run a mutated build
"""
import base64
import json
import os
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from zoneinfo import ZoneInfo

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
JAR = os.path.join(REPO, "dist", "logstash", "logstash.jar")
JAVA = os.path.join(os.environ.get("JAVA_HOME", "/Users/tangming/tools/jdk-21.0.12.1+1/Contents/Home"), "bin", "java")
TASK = json.load(open(os.path.join(REPO, "task.json"), encoding="utf-8"))

FAILURES = []


# --------------------------------------------------------------------------- the runner's contract

def base_input(**overrides):
    """task.json defaults, the way the runner layers them, plus the build environment the job would have."""
    data = {name: spec.get("default", "") for name, spec in TASK["input"].items()}
    data.update({"JOB_NAME": "demo", "BUILD_NUMBER": "42", "BUILD_STATUS": "SUCCESS", "NODE_NAME": "linux-1",
                 "BUILD_URL": "http://jenkins.example.com/job/demo/42/"})
    data.update(overrides)
    return data


def run(overrides, timeout=60):
    directory = tempfile.mkdtemp(prefix="logstash-check-")
    data = base_input(**overrides)
    data.setdefault("atom_workspace", directory)
    path = os.path.join(directory, "input.json")
    json.dump(data, open(path, "w", encoding="utf-8"), ensure_ascii=False)
    env = dict(os.environ)
    env.update({"atom_data_dir": directory, "atom_data_input": "input.json",
                "atom_data_output": "output.json", "atom_workspace": directory})
    # Pin the JVM's default zone away from the host's: the RFC 5424 frame must be GMT regardless of where this runs,
    # and on a UTC machine "local time" would look identical to GMT and hide that bug.
    proc = subprocess.run([JAVA, "-Duser.timezone=Asia/Shanghai", "-cp", JAR,
                           "com.jenkinschina.atom.sdk.AtomRunner"], cwd=directory, env=env,
                          capture_output=True, text=True, timeout=timeout)
    out = os.path.join(directory, "output.json")
    result = json.load(open(out, encoding="utf-8")) if os.path.exists(out) else {}
    values = {key: node.get("value") for key, node in (result.get("data") or {}).items()}
    return result, values, proc


def expect_error(result, code):
    assert result.get("status") == "error", f"expected an error, got {result.get('status')}: {result.get('message')}"
    assert result.get("errorCode") == code, f"expected error {code}, got {result.get('errorCode')}: {result.get('message')}"


# --------------------------------------------------------------------------- fake indexers

class UdpSink:
    """A UDP socket that keeps every datagram it is sent."""

    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(("127.0.0.1", 0))
        self.socket.settimeout(0.2)
        self.port = self.socket.getsockname()[1]
        self.packets = []
        self._stop = False
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

    def _loop(self):
        while not self._stop:
            try:
                data, _ = self.socket.recvfrom(65535)
            except (socket.timeout, OSError):
                continue
            self.packets.append(data)

    def wait(self, count=1, timeout=5.0):
        deadline = datetime.now() + timedelta(seconds=timeout)
        while len(self.packets) < count and datetime.now() < deadline:
            self.socket.settimeout(0.05)
        return self.packets

    def close(self):
        self._stop = True
        self.socket.close()


class RedisSink:
    """A RESP server: reads arrays of bulk strings, answers with whatever the test asked for."""

    def __init__(self, push_reply=":1", auth_reply="+OK"):
        self.commands = []
        self.push_reply = push_reply
        self.auth_reply = auth_reply
        self.server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), self._handler())
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def _handler(self):
        sink = self

        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                while True:
                    command = self._read_command()
                    if command is None:
                        return
                    sink.commands.append(command)
                    if command[0].upper() == "AUTH":
                        self.wfile.write((sink.auth_reply + "\r\n").encode())
                    else:
                        self.wfile.write((sink.push_reply + "\r\n").encode())
                    self.wfile.flush()

            def _read_command(self):
                line = self.rfile.readline()
                if not line:
                    return None
                assert line.startswith(b"*"), line
                count = int(line[1:].strip())
                args = []
                for _ in range(count):
                    size = int(self.rfile.readline()[1:].strip())
                    args.append(self.rfile.read(size).decode("utf-8"))
                    self.rfile.read(2)
                return args

        return Handler

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class HttpSink:
    """An HTTP server that records method, path, headers and body, and answers with a scripted status."""

    def __init__(self, status=200, body="{}"):
        self.requests = []
        sink = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                body = self.rfile.read(length).decode("utf-8")
                sink.requests.append({"method": "POST", "path": self.path, "headers": dict(self.headers),
                                      "body": body})
                payload = sink.body.encode()
                self.send_response(sink.status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args):
                pass

        self.status = status
        self.body = body
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def free_port():
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


# --------------------------------------------------------------------------- what the plugin would send

def expected_lines(message, max_lines):
    """Run#getLog(maxLines): 0 is an empty list, negative is the whole log, otherwise the last maxLines lines."""
    if message.endswith("\n"):
        message = message[:-1]
    lines = [] if message == "" else message.split("\n")
    if max_lines == 0:
        return []
    if max_lines < 0 or len(lines) <= max_lines:
        return lines
    return lines[len(lines) - max_lines:]


def expected_stamp(ms, zone, millis=True):
    """LogstashConfiguration#getDateFormatter: yyyy-MM-dd'T'HH:mm:ss.SSSZ (or without millis) in the local zone."""
    moment = datetime.fromtimestamp(ms / 1000, ZoneInfo(zone))
    base = moment.strftime("%Y-%m-%dT%H:%M:%S")
    return base + (".%03d" % (moment.microsecond // 1000) if millis else "") + moment.strftime("%z")


def expand_params(params):
    """Resolve ${VAR} in the inputs the way the atom does, with the build environment layered underneath."""
    import re

    def substitute(value):
        if not isinstance(value, str):
            return value
        return re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_]*)}",
                      lambda m: str(params.get(m.group(1), m.group(0))), value)

    return {key: substitute(value) for key, value in params.items()}


def get(params, name):
    """A params dict may come from FIXED or from task.json; treat a missing key like an empty input."""
    return params.get(name, "") or ""


def expected_data(params, zone):
    """BuildData as Gson writes it, from the same inputs, following the POJO's declaration order."""
    project = get(params, "projectName") or "demo"
    number = int(get(params, "buildNumber") or 0)
    display = get(params, "displayName") or "#%d" % number
    full_project = get(params, "fullProjectName") or project
    full_display = get(params, "fullDisplayName") or (full_project + " " + display)
    host = get(params, "buildHost") or get(params, "node") or "master"
    label = get(params, "buildLabel") or get(params, "label") or "master"
    data = {"id": get(params, "buildId") or str(number)}
    result = (get(params, "result") or "").strip().upper()
    if result and not result.startswith("${"):
        data["result"] = result
    data.update({
        "projectName": project,
        "fullProjectName": full_project,
        "displayName": display,
        "fullDisplayName": full_display,
        "description": get(params, "description"),
        "url": get(params, "buildUrl"),
        "buildHost": host,
        "buildLabel": label,
    })
    if get(params, "stageName"):
        data["stageName"] = get(params, "stageName")
    if get(params, "agentName"):
        data["agentName"] = get(params, "agentName")
    duration = int(get(params, "buildDurationMs") or 0)
    data.update({
        "buildNum": number,
        "buildDuration": duration,
        "rootProjectName": get(params, "rootProjectName") or project,
        "rootFullProjectName": get(params, "rootFullProjectName") or full_project,
        "rootProjectDisplayName": get(params, "rootProjectDisplayName") or display,
        "rootBuildNum": int(get(params, "rootBuildNum") or number),
        "buildVariables": expected_variables(params),
    })
    if (get(params, "testsTotal") or "").strip():
        total = int(get(params, "testsTotal"))
        skipped = int(get(params, "testsSkipped") or 0)
        failed = int(get(params, "testsFailed") or 0)
        details, names = [], []
        for line in (get(params, "failedTests") or "").split("\n"):
            if not line.strip():
                continue
            name, _, detail = line.partition("|")
            names.append(name.strip())
            item = {"fullName": name.strip()}
            if "|" in line:
                item["errorDetails"] = detail
            details.append(item)
        data["testResults"] = {"totalCount": total, "skipCount": skipped, "failCount": failed,
                               "passCount": total - skipped - failed,
                               "failedTestsWithErrorDetail": details, "failedTests": names}
    return data


def expected_variables(params):
    values = {}
    for line in (get(params, "buildVariables") or "").split("\n"):
        if not line.strip():
            continue
        key, _, value = line.partition("=")
        if key.strip() in [n.strip() for n in (get(params, "maskedVariables") or "").split(",") if n.strip()]:
            continue
        values[key.strip()] = value
    return values


def expected_payload(params, zone):
    """AbstractLogstashIndexerDao#buildPayload, over the runner's defaults."""
    params = expand_params({**base_input(), **params})
    payload = {
        "data": expected_data(params, zone),
        "message": expected_lines(get(params, "message"), int(get(params, "maxLines") or 100)),
        "source": "jenkins",
    }
    if get(params, "jenkinsUrl"):
        payload["source_host"] = get(params, "jenkinsUrl")
    millis = str(get(params, "millisecondTimestamps")).lower() != "false"
    build_ms = int(get(params, "buildTimestampMs") or get(params, "timestampMs") or 0)
    payload["@buildTimestamp"] = expected_stamp(build_ms, zone, millis)
    payload["@timestamp"] = expected_stamp(int(get(params, "timestampMs")), zone, millis)
    payload["@version"] = 1
    return payload


def syslog_frame(params, payload_json, zone):
    """SyslogDao#push + SyslogMessage: PRI 14, app name 'jenkins:' and the ': ' the sender appends, then CEE."""
    stamp = datetime.fromtimestamp(int(get(params, "timestampMs")) / 1000, ZoneInfo(zone))
    host = get(params, "host")
    if get(params, "syslogFormat") == "rfc5424":
        utc = datetime.fromtimestamp(int(get(params, "timestampMs")) / 1000, timezone.utc)
        return ("<14>1 " + utc.strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ" % (utc.microsecond // 1000)
                + " " + host + " jenkins: - - -  @cee: " + payload_json)
    return ("<14>" + stamp.strftime("%b %d %H:%M:%S") + " " + host + " jenkins::  @cee: " + payload_json)


def resp_command(*args):
    out = "*%d\r\n" % len(args)
    for arg in args:
        raw = arg.encode("utf-8")
        out += "$%d\r\n" % len(raw) + arg + "\r\n"
    return out.encode("utf-8")


# --------------------------------------------------------------------------- the checks

FIXED = {
    "projectName": "demo", "buildNumber": "42", "result": "UNSTABLE",
    "message": "line one\nline two\nline three\n",
    "buildUrl": "job/demo/42/", "buildLabel": "linux",
    "buildTimestampMs": "1762000000000", "timestampMs": "1762000005000",
    "timezone": "Asia/Shanghai", "buildDurationMs": "1500",
    "jenkinsUrl": "http://jenkins.example.com/",
    "buildVariables": "BRANCH=main\nTOKEN=secret\n", "maskedVariables": "TOKEN",
    "testsTotal": "10", "testsSkipped": "2", "testsFailed": "1", "failedTests": "a.B|boom\n",
}

CHECKS = []


def check(name):
    def register(fn):
        CHECKS.append((name, fn))
        return fn
    return register


@check("payload.syslog.rfc3164")
def _():
    sink = UdpSink()
    try:
        params = dict(FIXED, indexer="syslog", host="127.0.0.1", port=str(sink.port))
        result, values, _ = run(params)
        assert result["status"] == "success", result.get("message")
        packets = sink.wait(1)
        assert len(packets) == 1, f"expected one datagram, got {len(packets)}"
        frame = packets[0].decode("utf-8")
        payload = expected_payload(params, "Asia/Shanghai")
        expected = syslog_frame(params, json.dumps(payload, separators=(",", ":"), ensure_ascii=False), "Asia/Shanghai")
        assert frame == expected, "frame differs\n got: %s\nwant: %s" % (frame[:400], expected[:400])
        # and the frame's JSON really is the payload, with the declared field order
        body = json.loads(frame.split(" @cee: ", 1)[1])
        assert list(body) == ["data", "message", "source", "source_host", "@buildTimestamp", "@timestamp", "@version"], list(body)
        assert list(body["data"]) == list(payload["data"]), list(body["data"])
        assert body == payload, "payload body differs from the plugin's"
        assert isinstance(body["@version"], int) and body["@version"] == 1
        assert isinstance(body["data"]["buildNum"], int) and isinstance(body["data"]["buildDuration"], int)
        assert body["data"]["buildDuration"] == 1500
        assert values["payload"] == frame.split(" @cee: ", 1)[1]
    finally:
        sink.close()


@check("payload.nulls.and.types")
def _():
    params = dict(FIXED, indexer="redis", dryRun="true", result="${NO_SUCH_VARIABLE}", jenkinsUrl="",
                  description="", testsTotal="", stageName="", agentName="")
    result, values, _ = run(params)
    assert result["status"] == "success", result.get("message")
    body = json.loads(values["payload"])
    data = body["data"]
    assert "result" not in data, "an unfinished build has no result"
    assert "testResults" not in data, "no test action means no testResults"
    assert "stageName" not in data and "agentName" not in data
    assert "source_host" not in body, "a null root URL drops source_host"
    assert data["description"] == "", "build.getDescription() is an empty string, not null"
    assert data["buildHost"] == "linux-1" and data["buildLabel"] == "linux", (data["buildHost"], data["buildLabel"])
    assert data["id"] == "42" and data["displayName"] == "#42" and data["fullDisplayName"] == "demo #42"
    assert "timestamp" not in data and "build" not in data, "transient fields are not serialised"
    assert data["buildVariables"] == {"BRANCH": "main"}, data["buildVariables"]


@check("payload.tests")
def _():
    params = dict(FIXED, indexer="redis", dryRun="true", testsTotal="10", testsSkipped="3", testsFailed="2",
                  failedTests="a.B|boom\nc.D|\n")
    result, values, _ = run(params)
    assert result["status"] == "success", result.get("message")
    tests = json.loads(values["payload"])["data"]["testResults"]
    assert tests == {"totalCount": 10, "skipCount": 3, "failCount": 2, "passCount": 5,
                     "failedTestsWithErrorDetail": [{"fullName": "a.B", "errorDetails": "boom"},
                                                    {"fullName": "c.D", "errorDetails": ""}],
                     "failedTests": ["a.B", "c.D"]}, tests


@check("payload.maxlines.tail")
def _():
    message = "\n".join("L%d" % i for i in range(1, 251))
    params = dict(FIXED, indexer="redis", dryRun="true", message=message, maxLines="100")
    result, values, _ = run(params)
    assert result["status"] == "success", result.get("message")
    lines = json.loads(values["payload"])["message"]
    assert len(lines) == 100 and lines[0] == "L151" and lines[-1] == "L250", (len(lines), lines[:2], lines[-1])
    assert values["lines"] == "100"


@check("payload.maxlines.zero")
def _():
    params = dict(FIXED, indexer="redis", dryRun="true", maxLines="0")
    result, values, _ = run(params)
    assert result["status"] == "success", result.get("message")
    assert json.loads(values["payload"])["message"] == [], "Run#getLog(0) returns an empty list"


@check("payload.maxlines.all")
def _():
    params = dict(FIXED, indexer="redis", dryRun="true", maxLines="-1", message="a\nb\nc")
    result, values, _ = run(params)
    assert result["status"] == "success", result.get("message")
    assert json.loads(values["payload"])["message"] == ["a", "b", "c"]


@check("syslog.rfc5424")
def _():
    sink = UdpSink()
    try:
        params = dict(FIXED, indexer="syslog", syslogFormat="rfc5424", host="127.0.0.1", port=str(sink.port),
                      message="one\ntwo", result="SUCCESS")
        result, _, _ = run(params)
        assert result["status"] == "success", result.get("message")
        frame = sink.wait(1)[0].decode("utf-8")
        payload = expected_payload(params, "Asia/Shanghai")
        expected = syslog_frame(params, json.dumps(payload, separators=(",", ":"), ensure_ascii=False), "Asia/Shanghai")
        assert frame == expected, f"frame differs\n got: {frame[:300]}\nwant: {expected[:300]}"
        assert frame.startswith("<14>1 2025-11-01T12:26:45.000Z 127.0.0.1 jenkins: - - -  @cee: {"), frame[:80]
    finally:
        sink.close()


@check("syslog.timezone")
def _():
    """The 3164 header is local time and the payload stamps carry that zone's offset, for each zone asked for."""
    for zone, header, stamp in (("Asia/Shanghai", "<14>Nov 01 20:26:45 ", "2025-11-01T20:26:45.000+0800"),
                                ("UTC", "<14>Nov 01 12:26:45 ", "2025-11-01T12:26:45.000+0000")):
        sink = UdpSink()
        try:
            params = dict(FIXED, indexer="syslog", host="127.0.0.1", port=str(sink.port), timezone=zone)
            result, values, _ = run(params)
            assert result["status"] == "success", result.get("message")
            frame = sink.wait(1)[0].decode("utf-8")
            assert frame.startswith(header + "127.0.0.1 jenkins::  @cee: "), (zone, frame[:80])
            assert ('"@timestamp":"%s"' % stamp) in values["payload"], (zone, values["payload"][:200])
        finally:
            sink.close()


@check("syslog.legacy.seconds")
def _():
    sink = UdpSink()
    try:
        params = dict(FIXED, indexer="syslog", host="127.0.0.1", port=str(sink.port), millisecondTimestamps="false")
        result, values, _ = run(params)
        assert result["status"] == "success", result.get("message")
        body = json.loads(values["payload"])
        assert body["@timestamp"] == "2025-11-01T20:26:45+0800", body["@timestamp"]
        assert body["@buildTimestamp"] == "2025-11-01T20:26:40+0800"
        frame = sink.wait(1)[0].decode("utf-8")
        assert ".000" not in frame.split(" @cee: ")[1][:120]
    finally:
        sink.close()


@check("redis.auth.and.rpush")
def _():
    sink = RedisSink()
    try:
        params = dict(FIXED, indexer="redis", host="127.0.0.1", port=str(sink.port), redisKey="logstash",
                      redisPassword="s3cret")
        result, values, _ = run(params)
        assert result["status"] == "success", result.get("message")
        payload = json.dumps(expected_payload(params, "Asia/Shanghai"), separators=(",", ":"), ensure_ascii=False)
        assert sink.commands == [["AUTH", "s3cret"], ["RPUSH", "logstash", payload]], [
            c[:2] for c in sink.commands]
        assert values["reply"] == "rpush 1"
        assert values["payload"] == payload
    finally:
        sink.close()


@check("redis.no.password")
def _():
    sink = RedisSink()
    try:
        params = dict(FIXED, indexer="redis", host="127.0.0.1", port=str(sink.port), redisPassword="")
        result, _, _ = run(params)
        assert result["status"] == "success", result.get("message")
        assert len(sink.commands) == 1 and sink.commands[0][0] == "RPUSH", sink.commands
    finally:
        sink.close()


@check("redis.refused")
def _():
    sink = RedisSink(push_reply="-ERR maxmemory")
    try:
        params = dict(FIXED, indexer="redis", host="127.0.0.1", port=str(sink.port))
        result, _, _ = run(params)
        expect_error(result, 40010)
        assert "maxmemory" in result["message"], result["message"]
    finally:
        sink.close()


@check("redis.zero.length")
def _():
    sink = RedisSink(push_reply=":0")
    try:
        params = dict(FIXED, indexer="redis", host="127.0.0.1", port=str(sink.port))
        result, _, _ = run(params)
        expect_error(result, 40010)
        assert "RPUSH returned 0" in result["message"], result["message"]
    finally:
        sink.close()


@check("es.post")
def _():
    sink = HttpSink()
    try:
        params = dict(FIXED, indexer="elasticsearch", esUri="http://127.0.0.1:%d/logstash" % sink.port,
                      esUsername="elastic", esPassword="changeme")
        result, values, _ = run(params)
        assert result["status"] == "success", result.get("message")
        assert len(sink.requests) == 1, sink.requests
        request = sink.requests[0]
        assert request["method"] == "POST" and request["path"] == "/logstash", request["path"]
        assert request["headers"]["Content-Type"] == "application/json; charset=UTF-8", request["headers"]
        expected_auth = "Basic " + base64.b64encode(b"elastic:changeme").decode()
        assert request["headers"]["Authorization"] == expected_auth, request["headers"].get("Authorization")
        assert request["body"] == json.dumps(expected_payload(params, "Asia/Shanghai"),
                                             separators=(",", ":"), ensure_ascii=False)
        assert values["reply"] == "http 200"
    finally:
        sink.close()


@check("es.mimetype.override")
def _():
    sink = HttpSink()
    try:
        params = dict(FIXED, indexer="elasticsearch", esUri="http://127.0.0.1:%d/logstash" % sink.port,
                      mimeType="application/x-ndjson", esUsername="")
        result, _, _ = run(params)
        assert result["status"] == "success", result.get("message")
        headers = sink.requests[0]["headers"]
        assert headers["Content-Type"] == "application/x-ndjson", headers
        assert "Authorization" not in headers, "no username means no Authorization header"
    finally:
        sink.close()


@check("es.error")
def _():
    sink = HttpSink(status=500, body='{"error":"index closed"}')
    try:
        params = dict(FIXED, indexer="elasticsearch", esUri="http://127.0.0.1:%d/logstash" % sink.port)
        result, _, _ = run(params)
        expect_error(result, 40010)
        assert "HTTP error code: 500" in result["message"], result["message"]
        assert "index closed" in result["message"], result["message"]
    finally:
        sink.close()


@check("transport.unreachable")
def _():
    params = dict(FIXED, indexer="redis", host="127.0.0.1", port=str(free_port()))
    result, _, _ = run(params)
    expect_error(result, 40010)
    assert "could not send to redis" in result["message"], result["message"]


@check("failonerror.false")
def _():
    params = dict(FIXED, indexer="redis", host="127.0.0.1", port=str(free_port()), failOnError="false")
    result, values, _ = run(params)
    assert result["status"] == "success", result.get("message")
    assert "could not send" in result["message"], result["message"]
    assert values["payload"], "the payload is still reported"


@check("dryrun.sends.nothing")
def _():
    sink = UdpSink()
    try:
        params = dict(FIXED, indexer="syslog", host="127.0.0.1", port=str(sink.port), dryRun="true")
        result, values, _ = run(params)
        assert result["status"] == "success", result.get("message")
        assert sink.packets == [], "a dry run must not put a datagram on the wire"
        assert values["payload"], "a dry run still reports the payload"
    finally:
        sink.close()


@check("validation")
def _():
    cases = [
        ({"indexer": "kafka"}, 40003, "indexer must be"),
        ({"indexer": "rabbitmq"}, 40003, "not ported"),
        ({"indexer": "elasticsearch", "esUri": ""}, 40001, "esUri is required"),
        ({"indexer": "elasticsearch", "esUri": "ftp://x/logs"}, 40001, "http(s)"),
        ({"indexer": "syslog", "syslogFormat": "rfc9999"}, 40003, "rfc3164 or rfc5424"),
        ({"indexer": "redis", "port": "99999"}, 40001, "between 1 and 65535"),
        ({"indexer": "redis", "port": "abc"}, 40001, "port must be an integer"),
        ({"buildVariables": "not a pair"}, 40004, "key=value"),
        ({"testsTotal": "many"}, 40004, "must be an integer"),
        ({"buildNumber": "x"}, 40004, "buildNumber"),
        ({"timezone": "Mars/Olympus"}, 40003, "timezone"),
    ]
    for overrides, code, needle in cases:
        params = dict(FIXED, **overrides)
        result, _, _ = run(params)
        expect_error(result, code)
        assert needle in result["message"], (overrides, result["message"])


@check("payload.utf8")
def _():
    sink = UdpSink()
    try:
        params = dict(FIXED, indexer="syslog", host="127.0.0.1", port=str(sink.port),
                      message="构建开始 ✓\n日本語", description="描述")
        result, values, _ = run(params)
        assert result["status"] == "success", result.get("message")
        frame = sink.wait(1)[0].decode("utf-8")
        assert "构建开始 ✓" in frame and "日本語" in frame
        payload = json.loads(values["payload"])
        assert payload["message"] == ["构建开始 ✓", "日本語"]
        assert int(values["bytes"]) == len(values["payload"].encode("utf-8"))
    finally:
        sink.close()


@check("redis.payload.is.one.command")
def _():
    sink = RedisSink()
    try:
        params = dict(FIXED, indexer="redis", host="127.0.0.1", port=str(sink.port), message="a\nb")
        result, values, _ = run(params)
        assert result["status"] == "success", result.get("message")
        assert [c[0] for c in sink.commands] == ["RPUSH"], sink.commands
        assert sink.commands[0][1] == "logstash"
        assert json.loads(sink.commands[0][2])["message"] == ["a", "b"]
    finally:
        sink.close()


# --------------------------------------------------------------------------- runner

def main(argv):
    global JAR
    args = list(argv[1:])
    if "--jar" in args:
        index = args.index("--jar")
        JAR = args[index + 1]
        del args[index:index + 2]
    pattern = args[0] if args else ""
    ran = failed = 0
    for name, fn in CHECKS:
        if pattern and pattern not in name:
            continue
        ran += 1
        try:
            fn()
            print("ok   " + name)
        except AssertionError as e:
            failed += 1
            detail = str(e).splitlines() or [type(e).__name__]
            print("FAIL " + name + ": " + detail[0][:400])
        except Exception as e:  # noqa: BLE001
            failed += 1
            print("ERROR " + name + ": " + type(e).__name__ + ": " + str(e).splitlines()[0][:300])
    print("\n%d/%d checks passed" % (ran - failed, ran))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
