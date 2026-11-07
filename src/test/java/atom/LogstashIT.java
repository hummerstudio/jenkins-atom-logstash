package atom;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.jenkinschina.atom.sdk.Json;
import com.jenkinschina.atom.sdk.testing.Atom;
import com.jenkinschina.atom.sdk.testing.AtomResult;
import com.sun.net.httpserver.HttpServer;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The logstash atom against fake indexers that record the raw bytes: a UDP socket, a RESP server and an HTTP server.
 *
 * <p>The payload is recomputed here from the same inputs, following {@code AbstractLogstashIndexerDao#buildPayload} and
 * the {@code BuildData} POJO's declaration order, so a field the atom drops, renames or reorders is a failure — not a
 * number copied into the test.
 */
class LogstashIT {

    private static final String ZONE = "Asia/Shanghai";

    /** The build the cases describe: one unstable build with a log, variables and tests. */
    private static final Map<String, String> FIXED = Map.ofEntries(
            Map.entry("projectName", "demo"),
            Map.entry("buildNumber", "42"),
            Map.entry("result", "UNSTABLE"),
            Map.entry("message", "line one\nline two\nline three\n"),
            Map.entry("buildUrl", "job/demo/42/"),
            Map.entry("buildLabel", "linux"),
            Map.entry("buildTimestampMs", "1762000000000"),
            Map.entry("timestampMs", "1762000005000"),
            Map.entry("timezone", ZONE),
            Map.entry("buildDurationMs", "1500"),
            Map.entry("jenkinsUrl", "http://jenkins.example.com/"),
            Map.entry("buildVariables", "BRANCH=main\nTOKEN=secret\n"),
            Map.entry("maskedVariables", "TOKEN"),
            Map.entry("testsTotal", "10"),
            Map.entry("testsSkipped", "2"),
            Map.entry("testsFailed", "1"),
            Map.entry("failedTests", "a.B|boom\n"));

    private UdpSink udp;
    private RedisSink redis;
    private HttpSink http;

    @BeforeEach
    void setUp() throws Exception {
        udp = new UdpSink();
        redis = new RedisSink(":1", "+OK");
        http = new HttpSink(200, "{}");
    }

    @AfterEach
    void tearDown() {
        for (AutoCloseable sink : List.of(udp, redis, http)) {
            try {
                sink.close();
            } catch (Exception ignored) {
                // the sinks are test scaffolding: a failure to close must not mask the assertion that failed
            }
        }
    }

    // ---------------------------------------------------------------- the payload

    @Test
    @DisplayName("syslog rfc3164: PRI 14, the doubled colon, and the payload the plugin would build")
    void syslogRfc3164() throws Exception {
        Map<String, String> params = params(Map.of("indexer", "syslog", "host", "127.0.0.1",
                "port", String.valueOf(udp.port)));

        AtomResult run = run(params);

        run.assertOk();
        List<String> packets = udp.wait(1);
        assertEquals(1, packets.size(), "expected one datagram, got " + packets.size());
        String frame = packets.get(0);
        Map<String, Object> expected = payload(params);
        assertEquals(frameHeader(params) + run.field("payload"), frame,
                "frame differs\n got: " + head(frame) + "\nwant: " + head(frameHeader(params) + run.field("payload")));

        String body = frame.split(" @cee: ", 2)[1];
        Map<String, Object> sent = object(body);
        assertEquals(List.of("data", "message", "source", "source_host", "@buildTimestamp", "@timestamp", "@version"),
                List.copyOf(sent.keySet()), "the payload's field order");
        assertEquals(List.copyOf(object(expected.get("data")).keySet()),
                List.copyOf(object(sent.get("data")).keySet()), "the BuildData field order");
        assertEquals(normalize(expected), normalize(sent), "the payload body differs from the plugin's");
        assertInstanceOf(Number.class, sent.get("@version"), "@version must be a number");
        assertEquals("1", String.valueOf(sent.get("@version")));
        assertInstanceOf(Number.class, object(sent.get("data")).get("buildNum"), "buildNum must be a number");
        assertInstanceOf(Number.class, object(sent.get("data")).get("buildDuration"), "buildDuration must be a number");
        assertEquals("1500", String.valueOf(object(sent.get("data")).get("buildDuration")));
        assertEquals(body, run.field("payload"), "the reported payload must be what went on the wire");
        assertFalse(body.contains(", ") || body.contains(": "), "the payload must be compact JSON:\n" + head(body));
    }

    @Test
    @DisplayName("nulls and types: an unfinished build has no result, no tests, no source_host, and no transient fields")
    void nullsAndTypes() throws Exception {
        Map<String, String> params = params(Map.of("indexer", "redis", "dryRun", "true",
                "result", "${NO_SUCH_VARIABLE}", "jenkinsUrl", "", "description", "",
                "testsTotal", "", "stageName", "", "agentName", ""));

        AtomResult run = run(params);

        run.assertOk();
        Map<String, Object> body = object(run.field("payload"));
        Map<String, Object> data = object(body.get("data"));
        assertFalse(data.containsKey("result"), "an unfinished build has no result");
        assertFalse(data.containsKey("testResults"), "no test action means no testResults");
        assertFalse(data.containsKey("stageName"), data.toString());
        assertFalse(data.containsKey("agentName"), data.toString());
        assertFalse(body.containsKey("source_host"), "a null root URL drops source_host");
        assertEquals("", data.get("description"), "build.getDescription() is an empty string, not null");
        assertEquals("linux-1", data.get("buildHost"), String.valueOf(data));
        assertEquals("linux", data.get("buildLabel"));
        assertEquals("42", data.get("id"));
        assertEquals("#42", data.get("displayName"));
        assertEquals("demo #42", data.get("fullDisplayName"));
        assertFalse(data.containsKey("timestamp") || data.containsKey("build"), "transient fields are not serialised");
        assertEquals(Map.of("BRANCH", "main"), data.get("buildVariables"), String.valueOf(data.get("buildVariables")));
    }

    @Test
    @DisplayName("test results: passCount is total - skipped - failed, and both failure shapes are written")
    void testResults() throws Exception {
        Map<String, String> params = params(Map.of("indexer", "redis", "dryRun", "true",
                "testsTotal", "10", "testsSkipped", "3", "testsFailed", "2", "failedTests", "a.B|boom\nc.D|\n"));

        AtomResult run = run(params);

        run.assertOk();
        Object tests = object(run.field("payload")).get("data");
        Object value = object(tests).get("testResults");
        assertEquals(normalize(Map.of(
                "totalCount", 10, "skipCount", 3, "failCount", 2, "passCount", 5,
                "failedTestsWithErrorDetail", List.of(
                        Map.of("fullName", "a.B", "errorDetails", "boom"),
                        Map.of("fullName", "c.D", "errorDetails", "")),
                "failedTests", List.of("a.B", "c.D"))), normalize(value), String.valueOf(value));
    }

    @Test
    @DisplayName("maxLines: the last N lines, in order")
    void maxLinesTail() throws Exception {
        StringBuilder message = new StringBuilder();
        for (int i = 1; i <= 250; i++) {
            message.append("L").append(i).append('\n');
        }
        Map<String, String> params = params(Map.of("indexer", "redis", "dryRun", "true",
                "message", message.toString(), "maxLines", "100"));

        AtomResult run = run(params);

        run.assertOk();
        List<?> lines = (List<?>) object(run.field("payload")).get("message");
        assertEquals(100, lines.size(), "line count");
        assertEquals("L151", lines.get(0));
        assertEquals("L250", lines.get(99));
        assertEquals("100", run.field("lines"));
    }

    @Test
    @DisplayName("maxLines=0 sends no log lines at all")
    void maxLinesZero() throws Exception {
        AtomResult run = run(params(Map.of("indexer", "redis", "dryRun", "true", "maxLines", "0")));

        run.assertOk();
        assertEquals(List.of(), object(run.field("payload")).get("message"), "Run#getLog(0) returns an empty list");
    }

    @Test
    @DisplayName("a negative maxLines sends the whole log")
    void maxLinesAll() throws Exception {
        AtomResult run = run(params(Map.of("indexer", "redis", "dryRun", "true",
                "maxLines", "-1", "message", "a\nb\nc")));

        run.assertOk();
        assertEquals(List.of("a", "b", "c"), object(run.field("payload")).get("message"));
    }

    @Test
    @DisplayName("utf-8: a Chinese log survives the frame, the payload and the byte count")
    void utf8() throws Exception {
        Map<String, String> params = params(Map.of("indexer", "syslog", "host", "127.0.0.1",
                "port", String.valueOf(udp.port), "message", "构建开始 ✓\n日本語", "description", "描述"));

        AtomResult run = run(params);

        run.assertOk();
        String frame = udp.wait(1).get(0);
        assertTrue(frame.contains("构建开始 ✓") && frame.contains("日本語"), head(frame));
        assertEquals(List.of("构建开始 ✓", "日本語"), object(run.field("payload")).get("message"));
        assertEquals(run.field("payload").getBytes(StandardCharsets.UTF_8).length,
                Integer.parseInt(run.field("bytes")), "the byte count must be the UTF-8 length");
    }

    // ---------------------------------------------------------------- syslog

    @Test
    @DisplayName("syslog rfc5424: GMT, the nil PROCID/MSGID/structured data, and the same payload")
    void syslogRfc5424() throws Exception {
        Map<String, String> params = params(Map.of("indexer", "syslog", "syslogFormat", "rfc5424",
                "host", "127.0.0.1", "port", String.valueOf(udp.port), "message", "one\ntwo", "result", "SUCCESS"));

        AtomResult run = run(params);

        run.assertOk();
        String frame = udp.wait(1).get(0);
        String expected = frameHeader(params) + run.field("payload");
        assertEquals(head(expected), head(frame), "frame differs");
        assertEquals(expected, frame, "frame differs");
        assertTrue(frame.startsWith("<14>1 2025-11-01T12:26:45.000Z 127.0.0.1 jenkins: - - -  @cee: {"), head(frame));
    }

    @Test
    @DisplayName("the 3164 header is local time and the payload stamps carry that zone's offset, for each zone asked for")
    void syslogTimezone() throws Exception {
        record Case(String zone, String header, String stamp) {}
        for (Case each : List.of(
                new Case("Asia/Shanghai", "<14>Nov 01 20:26:45 ", "2025-11-01T20:26:45.000+0800"),
                new Case("UTC", "<14>Nov 01 12:26:45 ", "2025-11-01T12:26:45.000+0000"))) {
            UdpSink sink = new UdpSink();
            try {
                Map<String, String> params = params(Map.of("indexer", "syslog", "host", "127.0.0.1",
                        "port", String.valueOf(sink.port), "timezone", each.zone()));

                AtomResult run = run(params);

                run.assertOk();
                String frame = sink.wait(1).get(0);
                assertTrue(frame.startsWith(each.header() + "127.0.0.1 jenkins::  @cee: "),
                        each.zone() + ": " + head(frame));
                assertTrue(run.field("payload").contains("\"@timestamp\":\"" + each.stamp() + "\""),
                        each.zone() + ": " + head(run.field("payload")));
            } finally {
                sink.close();
            }
        }
    }

    @Test
    @DisplayName("millisecondTimestamps=false falls back to the older second-precision stamp")
    void syslogLegacySeconds() throws Exception {
        Map<String, String> params = params(Map.of("indexer", "syslog", "host", "127.0.0.1",
                "port", String.valueOf(udp.port), "millisecondTimestamps", "false"));

        AtomResult run = run(params);

        run.assertOk();
        Map<String, Object> body = object(run.field("payload"));
        assertEquals("2025-11-01T20:26:45+0800", body.get("@timestamp"), String.valueOf(body.get("@timestamp")));
        assertEquals("2025-11-01T20:26:40+0800", body.get("@buildTimestamp"));
        String wire = udp.wait(1).get(0).split(" @cee: ", 2)[1];
        assertFalse(wire.substring(0, Math.min(120, wire.length())).contains(".000"),
                "the legacy stamp must not carry milliseconds");
    }

    // ---------------------------------------------------------------- redis

    @Test
    @DisplayName("redis: AUTH first when a password is set, then RPUSH with the payload")
    void redisAuthAndRpush() throws Exception {
        Map<String, String> params = params(Map.of("indexer", "redis", "host", "127.0.0.1",
                "port", String.valueOf(redis.port), "redisKey", "logstash", "redisPassword", "s3cret"));

        AtomResult run = run(params);

        run.assertOk();
        String payload = run.field("payload");
        assertEquals(List.of(List.of("AUTH", "s3cret"), List.of("RPUSH", "logstash", payload)), redis.commands,
                "the RESP command sequence");
        assertEquals("rpush 1", run.field("reply"));
        assertEquals(Json.write(normalize(payload(params))), payload, "the payload must be the plugin's");
    }

    @Test
    @DisplayName("redis: no password means no AUTH")
    void redisWithoutPassword() throws Exception {
        AtomResult run = run(params(Map.of("indexer", "redis", "host", "127.0.0.1",
                "port", String.valueOf(redis.port), "redisPassword", "")));

        run.assertOk();
        assertEquals(1, redis.commands.size(), String.valueOf(redis.commands));
        assertEquals("RPUSH", redis.commands.get(0).get(0), String.valueOf(redis.commands));
    }

    @Test
    @DisplayName("redis: an -ERR reply is a failure carrying the reason")
    void redisRefused() throws Exception {
        RedisSink sink = new RedisSink("-ERR maxmemory", "+OK");
        try {
            AtomResult run = run(params(Map.of("indexer", "redis", "host", "127.0.0.1",
                    "port", String.valueOf(sink.port))));

            run.assertRefused();
            assertEquals("40010", String.valueOf(run.document().get("errorCode")), message(run));
            assertTrue(message(run).contains("maxmemory"), message(run));
        } finally {
            sink.close();
        }
    }

    @Test
    @DisplayName("redis: a zero-length push is a failure, not a success")
    void redisZeroLength() throws Exception {
        RedisSink sink = new RedisSink(":0", "+OK");
        try {
            AtomResult run = run(params(Map.of("indexer", "redis", "host", "127.0.0.1",
                    "port", String.valueOf(sink.port))));

            run.assertRefused();
            assertEquals("40010", String.valueOf(run.document().get("errorCode")), message(run));
            assertTrue(message(run).contains("RPUSH returned 0"), message(run));
        } finally {
            sink.close();
        }
    }

    @Test
    @DisplayName("redis: the payload is one RPUSH, not one per line")
    void redisPayloadIsOneCommand() throws Exception {
        AtomResult run = run(params(Map.of("indexer", "redis", "host", "127.0.0.1",
                "port", String.valueOf(redis.port), "message", "a\nb")));

        run.assertOk();
        assertEquals(List.of("RPUSH"), redis.commands.stream().map(command -> command.get(0)).toList());
        assertEquals("logstash", redis.commands.get(0).get(1));
        assertEquals(List.of("a", "b"), object(redis.commands.get(0).get(2)).get("message"));
    }

    // ---------------------------------------------------------------- elasticsearch

    @Test
    @DisplayName("elasticsearch: POST of the payload, the plugin's Content-Type and Basic auth")
    void elasticsearchPost() throws Exception {
        Map<String, String> params = params(Map.of("indexer", "elasticsearch",
                "esUri", "http://127.0.0.1:" + http.port + "/logstash",
                "esUsername", "elastic", "esPassword", "changeme"));

        AtomResult run = run(params);

        run.assertOk();
        assertEquals(1, http.requests.size(), String.valueOf(http.requests));
        Request request = http.requests.get(0);
        assertEquals("POST", request.method());
        assertEquals("/logstash", request.path());
        assertEquals("application/json; charset=UTF-8", request.contentType(), String.valueOf(request.contentType()));
        assertEquals("Basic " + Base64.getEncoder().encodeToString("elastic:changeme".getBytes(StandardCharsets.UTF_8)),
                request.authorization(), "Basic auth");
        assertEquals(run.field("payload"), request.body(), "the body must be the payload");
        assertEquals(Json.write(normalize(payload(params))), request.body(), "the payload must be the plugin's");
        assertEquals("http 200", run.field("reply"));
    }

    @Test
    @DisplayName("elasticsearch: mimeType overrides the header, and no username means no Authorization")
    void elasticsearchMimeType() throws Exception {
        AtomResult run = run(params(Map.of("indexer", "elasticsearch",
                "esUri", "http://127.0.0.1:" + http.port + "/logstash",
                "mimeType", "application/x-ndjson", "esUsername", "")));

        run.assertOk();
        Request request = http.requests.get(0);
        assertEquals("application/x-ndjson", request.contentType());
        assertEquals(null, request.authorization(), "no username means no Authorization header");
    }

    @Test
    @DisplayName("elasticsearch: a 500 is a failure naming the status and the reason")
    void elasticsearchError() throws Exception {
        HttpSink sink = new HttpSink(500, "{\"error\":\"index closed\"}");
        try {
            AtomResult run = run(params(Map.of("indexer", "elasticsearch",
                    "esUri", "http://127.0.0.1:" + sink.port + "/logstash")));

            run.assertRefused();
            assertEquals("40010", String.valueOf(run.document().get("errorCode")), message(run));
            assertTrue(message(run).contains("HTTP error code: 500"), message(run));
            assertTrue(message(run).contains("index closed"), message(run));
        } finally {
            sink.close();
        }
    }

    // ---------------------------------------------------------------- failures

    @Test
    @DisplayName("an unreachable indexer is a failure, not a silent success")
    void transportUnreachable() throws Exception {
        AtomResult run = run(params(Map.of("indexer", "redis", "host", "127.0.0.1",
                "port", String.valueOf(freePort()))));

        run.assertRefused();
        assertEquals("40010", String.valueOf(run.document().get("errorCode")), message(run));
        assertTrue(message(run).contains("could not send to redis"), message(run));
    }

    @Test
    @DisplayName("failOnError=false makes the same failure a green step that still reports the payload")
    void failOnErrorFalse() throws Exception {
        AtomResult run = run(params(Map.of("indexer", "redis", "host", "127.0.0.1",
                "port", String.valueOf(freePort()), "failOnError", "false")));

        run.assertOk();
        assertTrue(message(run).contains("could not send"), message(run));
        assertFalse(run.field("payload").isEmpty(), "the payload is still reported");
    }

    @Test
    @DisplayName("a dry run puts nothing on the wire but still reports the payload")
    void dryRunSendsNothing() throws Exception {
        AtomResult run = run(params(Map.of("indexer", "syslog", "host", "127.0.0.1",
                "port", String.valueOf(udp.port), "dryRun", "true")));

        run.assertOk();
        assertEquals(List.of(), udp.wait(0), "a dry run must not put a datagram on the wire");
        assertFalse(run.field("payload").isEmpty(), "a dry run still reports the payload");
    }

    @Test
    @DisplayName("input validation: each refusal names its own problem")
    void validation() throws Exception {
        record Case(Map<String, String> overrides, String code, String needle) {}
        List<Case> cases = List.of(
                new Case(Map.of("indexer", "kafka"), "40003", "indexer must be"),
                new Case(Map.of("indexer", "rabbitmq"), "40003", "not ported"),
                new Case(Map.of("indexer", "elasticsearch", "esUri", ""), "40001", "esUri is required"),
                new Case(Map.of("indexer", "elasticsearch", "esUri", "ftp://x/logs"), "40001", "http(s)"),
                new Case(Map.of("indexer", "syslog", "syslogFormat", "rfc9999"), "40003", "rfc3164 or rfc5424"),
                new Case(Map.of("indexer", "redis", "port", "99999"), "40001", "between 1 and 65535"),
                new Case(Map.of("indexer", "redis", "port", "abc"), "40001", "port must be an integer"),
                new Case(Map.of("buildVariables", "not a pair"), "40004", "key=value"),
                new Case(Map.of("testsTotal", "many"), "40004", "must be an integer"),
                new Case(Map.of("buildNumber", "x"), "40004", "buildNumber"),
                new Case(Map.of("timezone", "Mars/Olympus"), "40003", "timezone"));

        for (Case each : cases) {
            Map<String, String> merged = new LinkedHashMap<>(FIXED);
            merged.putAll(each.overrides());
            AtomResult run = run(params(merged));

            run.assertRefused();
            assertEquals(each.code(), String.valueOf(run.document().get("errorCode")),
                    each.overrides() + ": " + message(run));
            assertTrue(message(run).contains(each.needle()), each.overrides() + ": " + message(run));
        }
    }

    // ---------------------------------------------------------------- the atom under test

    /** The runner's environment plus the case's inputs, exactly as the runner layers them into input.json. */
    private Map<String, String> params(Map<String, String> overrides) throws IOException {
        Map<String, String> all = new LinkedHashMap<>(defaults());
        all.put("JOB_NAME", "demo");
        all.put("BUILD_NUMBER", "42");
        all.put("BUILD_STATUS", "SUCCESS");
        all.put("NODE_NAME", "linux-1");
        all.put("BUILD_URL", "http://jenkins.example.com/job/demo/42/");
        all.putAll(FIXED);
        all.putAll(overrides);
        return all;
    }

    /** task.json's declared defaults — the same table the old check read. */
    private Map<String, String> defaults() throws IOException {
        Path task = Path.of(System.getProperty("atom.module", System.getProperty("user.dir"))).resolve("task.json");
        Map<String, Object> document = Json.parseObject(Files.readString(task, StandardCharsets.UTF_8));
        Map<String, String> defaults = new LinkedHashMap<>();
        Object input = document.get("input");
        if (input instanceof Map<?, ?> fields) {
            fields.forEach((key, spec) -> {
                Object value = spec instanceof Map<?, ?> map ? map.get("default") : null;
                defaults.put(String.valueOf(key), value == null ? "" : String.valueOf(value));
            });
        }
        return defaults;
    }

    private AtomResult run(Map<String, String> params) throws Exception {
        Atom instance = Atom.of();
        // the atom's JVM inherits this: use the same default zone the old harness pinned with -Duser.timezone
        instance.env("TZ", ZONE);
        params.forEach(instance::input);
        return instance.run();
    }

    // ---------------------------------------------------------------- what the plugin would send

    /** {@code AbstractLogstashIndexerDao#buildPayload}, over the runner's defaults. */
    private Map<String, Object> payload(Map<String, String> raw) {
        Map<String, String> params = expand(raw);
        String zone = get(params, "timezone").isEmpty() ? ZONE : get(params, "timezone");
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("data", data(params));
        payload.put("message", lines(get(params, "message"), integer(get(params, "maxLines"), 100)));
        payload.put("source", "jenkins");
        if (!get(params, "jenkinsUrl").isEmpty()) {
            payload.put("source_host", get(params, "jenkinsUrl"));
        }
        boolean millis = !"false".equalsIgnoreCase(get(params, "millisecondTimestamps"));
        long buildMs = longValue(get(params, "buildTimestampMs"), longValue(get(params, "timestampMs"), 0));
        payload.put("@buildTimestamp", stamp(buildMs, zone, millis));
        payload.put("@timestamp", stamp(longValue(get(params, "timestampMs"), 0), zone, millis));
        payload.put("@version", 1);
        return payload;
    }

    /** BuildData as Gson writes it, in the POJO's declaration order. */
    private Map<String, Object> data(Map<String, String> params) {
        String project = get(params, "projectName");
        int number = integer(get(params, "buildNumber"), 0);
        String display = or(get(params, "displayName"), "#" + number);
        String fullProject = or(get(params, "fullProjectName"), project);
        String fullDisplay = or(get(params, "fullDisplayName"), fullProject + " " + display);
        String host = or(or(get(params, "buildHost"), get(params, "node")), "master");
        String label = or(or(get(params, "buildLabel"), get(params, "label")), "master");

        Map<String, Object> data = new LinkedHashMap<>();
        data.put("id", or(get(params, "buildId"), String.valueOf(number)));
        String result = get(params, "result").strip().toUpperCase(Locale.ROOT);
        if (!result.isEmpty() && !result.startsWith("${")) {
            data.put("result", result);
        }
        data.put("projectName", project);
        data.put("fullProjectName", fullProject);
        data.put("displayName", display);
        data.put("fullDisplayName", fullDisplay);
        data.put("description", get(params, "description"));
        data.put("url", get(params, "buildUrl"));
        data.put("buildHost", host);
        data.put("buildLabel", label);
        if (!get(params, "stageName").isEmpty()) {
            data.put("stageName", get(params, "stageName"));
        }
        if (!get(params, "agentName").isEmpty()) {
            data.put("agentName", get(params, "agentName"));
        }
        data.put("buildNum", number);
        data.put("buildDuration", integer(get(params, "buildDurationMs"), 0));
        data.put("rootProjectName", or(get(params, "rootProjectName"), project));
        data.put("rootFullProjectName", or(get(params, "rootFullProjectName"), fullProject));
        data.put("rootProjectDisplayName", or(get(params, "rootProjectDisplayName"), display));
        data.put("rootBuildNum", integer(get(params, "rootBuildNum"), number));
        data.put("buildVariables", variables(params));
        if (!get(params, "testsTotal").strip().isEmpty()) {
            int total = integer(get(params, "testsTotal"), 0);
            int skipped = integer(get(params, "testsSkipped"), 0);
            int failed = integer(get(params, "testsFailed"), 0);
            List<Map<String, Object>> details = new ArrayList<>();
            List<String> names = new ArrayList<>();
            for (String line : get(params, "failedTests").split("\n")) {
                if (line.strip().isEmpty()) {
                    continue;
                }
                int bar = line.indexOf('|');
                String name = (bar < 0 ? line : line.substring(0, bar)).strip();
                names.add(name);
                Map<String, Object> item = new LinkedHashMap<>();
                item.put("fullName", name);
                if (bar >= 0) {
                    item.put("errorDetails", line.substring(bar + 1));
                }
                details.add(item);
            }
            Map<String, Object> tests = new LinkedHashMap<>();
            tests.put("totalCount", total);
            tests.put("skipCount", skipped);
            tests.put("failCount", failed);
            tests.put("passCount", total - skipped - failed);
            tests.put("failedTestsWithErrorDetail", details);
            tests.put("failedTests", names);
            data.put("testResults", tests);
        }
        return data;
    }

    private Map<String, Object> variables(Map<String, String> params) {
        List<String> masked = new ArrayList<>();
        for (String name : get(params, "maskedVariables").split(",")) {
            if (!name.strip().isEmpty()) {
                masked.add(name.strip());
            }
        }
        Map<String, Object> values = new LinkedHashMap<>();
        for (String line : get(params, "buildVariables").split("\n")) {
            if (line.strip().isEmpty()) {
                continue;
            }
            int equals = line.indexOf('=');
            String key = (equals < 0 ? line : line.substring(0, equals)).strip();
            if (masked.contains(key)) {
                continue;
            }
            values.put(key, equals < 0 ? "" : line.substring(equals + 1));
        }
        return values;
    }

    /** {@code Run#getLog(maxLines)}: 0 is empty, negative is the whole log, otherwise the last maxLines lines. */
    private static List<String> lines(String message, int maxLines) {
        String text = message.endsWith("\n") ? message.substring(0, message.length() - 1) : message;
        List<String> lines = text.isEmpty() ? List.of() : List.of(text.split("\n", -1));
        if (maxLines == 0) {
            return List.of();
        }
        if (maxLines < 0 || lines.size() <= maxLines) {
            return lines;
        }
        return lines.subList(lines.size() - maxLines, lines.size());
    }

    /** {@code LogstashConfiguration#getDateFormatter} in the requested zone. */
    private static String stamp(long ms, String zone, boolean millis) {
        ZonedDateTime moment = Instant.ofEpochMilli(ms).atZone(ZoneId.of(zone));
        String pattern = millis ? "yyyy-MM-dd'T'HH:mm:ss.SSSZ" : "yyyy-MM-dd'T'HH:mm:ssZ";
        return moment.format(DateTimeFormatter.ofPattern(pattern, Locale.ENGLISH));
    }

    /** SyslogDao#push + SyslogMessage: PRI 14, the app name plus its ": ", then CEE. */
    private static String frameHeader(Map<String, String> params) {
        long ms = Long.parseLong(get(params, "timestampMs"));
        String host = get(params, "host");
        if ("rfc5424".equals(get(params, "syslogFormat"))) {
            String utc = Instant.ofEpochMilli(ms).atZone(ZoneOffset.UTC)
                    .format(DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.ENGLISH));
            return "<14>1 " + utc + " " + host + " jenkins: - - -  @cee: ";
        }
        String zone = get(params, "timezone").isEmpty() ? ZONE : get(params, "timezone");
        String local = Instant.ofEpochMilli(ms).atZone(ZoneId.of(zone))
                .format(DateTimeFormatter.ofPattern("MMM dd HH:mm:ss", Locale.ENGLISH));
        return "<14>" + local + " " + host + " jenkins::  @cee: ";
    }

    private static Map<String, String> expand(Map<String, String> params) {
        Pattern reference = Pattern.compile("\\$\\{([A-Za-z_][A-Za-z0-9_]*)}");
        Map<String, String> expanded = new LinkedHashMap<>();
        params.forEach((key, value) -> {
            Matcher matcher = reference.matcher(value);
            StringBuilder out = new StringBuilder();
            while (matcher.find()) {
                matcher.appendReplacement(out, Matcher.quoteReplacement(
                        params.getOrDefault(matcher.group(1), matcher.group(0))));
            }
            matcher.appendTail(out);
            expanded.put(key, out.toString());
        });
        return expanded;
    }

    private static String get(Map<String, String> params, String name) {
        String value = params.get(name);
        return value == null ? "" : value;
    }

    private static String or(String value, String fallback) {
        return value == null || value.isEmpty() ? fallback : value;
    }

    private static int integer(String value, int fallback) {
        return value == null || value.isBlank() ? fallback : Integer.parseInt(value.trim());
    }

    private static long longValue(String value, long fallback) {
        return value == null || value.isBlank() ? fallback : Long.parseLong(value.trim());
    }

    private static int integer(String value) {
        return integer(value, 0);
    }

    /** A JSON object, given either the parsed node or the text — the atom's {@code payload} output is a string. */
    @SuppressWarnings("unchecked")
    private static Map<String, Object> object(Object value) {
        Object node = value instanceof String text ? Json.parse(text) : value;
        return node instanceof Map<?, ?> map ? (Map<String, Object>) map : Map.of();
    }

    /** Numbers compare by value whatever their Java type: the payload is JSON, not a Java object graph. */
    private static Object normalize(Object value) {
        if (value instanceof Map<?, ?> map) {
            Map<String, Object> copy = new LinkedHashMap<>();
            map.forEach((key, node) -> copy.put(String.valueOf(key), normalize(node)));
            return copy;
        }
        if (value instanceof List<?> list) {
            List<Object> copy = new ArrayList<>();
            list.forEach(node -> copy.add(normalize(node)));
            return copy;
        }
        if (value instanceof Number number) {
            double asDouble = number.doubleValue();
            return asDouble == Math.rint(asDouble) ? (Object) (long) asDouble : (Object) asDouble;
        }
        return value;
    }

    private static String message(AtomResult run) {
        return String.valueOf(run.document().getOrDefault("message", ""));
    }

    private static String head(String text) {
        return text.length() <= 300 ? text : text.substring(0, 300);
    }

    private static int freePort() throws IOException {
        try (ServerSocket probe = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"))) {
            return probe.getLocalPort();
        }
    }

    // ---------------------------------------------------------------- fake indexers

    /** A UDP socket that keeps every datagram it is sent. */
    private static final class UdpSink implements AutoCloseable {

        private final DatagramSocket socket;
        private final List<String> packets = new CopyOnWriteArrayList<>();
        private final int port;
        private volatile boolean stopped;

        UdpSink() throws IOException {
            socket = new DatagramSocket(0, InetAddress.getByName("127.0.0.1"));
            port = socket.getLocalPort();
            socket.setSoTimeout(200);
            Thread reader = new Thread(() -> {
                byte[] buffer = new byte[65535];
                while (!stopped) {
                    DatagramPacket packet = new DatagramPacket(buffer, buffer.length);
                    try {
                        socket.receive(packet);
                        packets.add(new String(packet.getData(), 0, packet.getLength(), StandardCharsets.UTF_8));
                    } catch (IOException ignored) {
                        // a timeout is how the reader notices it should look at stopped again
                    }
                }
            }, "udp-sink");
            reader.setDaemon(true);
            reader.start();
        }

        List<String> wait(int count) throws InterruptedException {
            long deadline = System.currentTimeMillis() + 5_000;
            while (packets.size() < count && System.currentTimeMillis() < deadline) {
                Thread.sleep(25);
            }
            return new ArrayList<>(packets);
        }

        @Override
        public void close() {
            stopped = true;
            socket.close();
        }
    }

    /** A RESP server: reads arrays of bulk strings, answers with whatever the case asked for. */
    private static final class RedisSink implements AutoCloseable {

        private final List<List<String>> commands = new CopyOnWriteArrayList<>();
        private final ServerSocket server;
        private final int port;
        private final String pushReply;
        private final String authReply;
        private volatile boolean stopped;

        RedisSink(String pushReply, String authReply) throws IOException {
            this.pushReply = pushReply;
            this.authReply = authReply;
            server = new ServerSocket(0, 4, InetAddress.getByName("127.0.0.1"));
            port = server.getLocalPort();
            Thread thread = new Thread(() -> {
                while (!stopped) {
                    try (Socket client = server.accept()) {
                        serve(client);
                    } catch (IOException ignored) {
                        // accept() fails when the socket is closed, which is how this loop ends
                    }
                }
            }, "resp-sink");
            thread.setDaemon(true);
            thread.start();
        }

        private void serve(Socket client) throws IOException {
            BufferedReader reader = new BufferedReader(new InputStreamReader(client.getInputStream(),
                    StandardCharsets.UTF_8));
            OutputStream out = client.getOutputStream();
            while (true) {
                String line = reader.readLine();
                if (line == null) {
                    return;
                }
                if (!line.startsWith("*")) {
                    throw new IOException("not a RESP array: " + line);
                }
                int count = Integer.parseInt(line.substring(1).trim());
                List<String> command = new ArrayList<>();
                for (int index = 0; index < count; index++) {
                    int size = Integer.parseInt(reader.readLine().substring(1).trim());
                    char[] body = new char[size];
                    int read = 0;
                    while (read < size) {
                        int n = reader.read(body, read, size - read);
                        if (n < 0) {
                            return;
                        }
                        read += n;
                    }
                    command.add(new String(body));
                    reader.read();
                    reader.read(); // the CRLF after the bulk string
                }
                commands.add(command);
                String reply = "AUTH".equalsIgnoreCase(command.get(0)) ? authReply : pushReply;
                out.write((reply + "\r\n").getBytes(StandardCharsets.UTF_8));
                out.flush();
            }
        }

        @Override
        public void close() throws IOException {
            stopped = true;
            server.close();
        }
    }

    private record Request(String method, String path, String contentType, String authorization, String body) {}

    /** An HTTP server that records method, path, headers and body, and answers with a scripted status. */
    private static final class HttpSink implements AutoCloseable {

        private final List<Request> requests = new CopyOnWriteArrayList<>();
        private final HttpServer server;
        private final int port;
        private final int status;
        private final String body;

        HttpSink(int status, String body) throws IOException {
            this.status = status;
            this.body = body;
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            port = server.getAddress().getPort();
            server.createContext("/", exchange -> {
                byte[] payload = exchange.getRequestBody().readAllBytes();
                requests.add(new Request(exchange.getRequestMethod(),
                        exchange.getRequestURI().getPath(),
                        exchange.getRequestHeaders().getFirst("Content-Type"),
                        exchange.getRequestHeaders().getFirst("Authorization"),
                        new String(payload, StandardCharsets.UTF_8)));
                byte[] reply = this.body.getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().add("Content-Type", "application/json");
                exchange.sendResponseHeaders(this.status, reply.length);
                try (OutputStream out = exchange.getResponseBody()) {
                    out.write(reply);
                }
                exchange.close();
            });
            server.start();
        }

        @Override
        public void close() {
            server.stop(0);
        }
    }
}
