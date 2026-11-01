package com.jenkinschina.atom.logstash;

import com.jenkinschina.atom.sdk.AtomContext;
import com.jenkinschina.atom.sdk.AtomResult;
import com.jenkinschina.atom.sdk.AtomTask;
import com.jenkinschina.atom.sdk.ErrorType;
import com.jenkinschina.atom.sdk.Json;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Send one build payload to a Logstash indexer - the transport half of the {@code logstash} plugin
 * (org.jenkins-ci.plugins:logstash 2.5.0).
 *
 * <p>The payload is {@code AbstractLogstashIndexerDao#buildPayload}: {@code data} (the Gson-serialised
 * {@code BuildData} POJO), {@code message} (the list of log lines), {@code source} = {@code jenkins},
 * {@code source_host} (the Jenkins root URL), {@code @buildTimestamp} (the build's start time),
 * {@code @timestamp} (now) and {@code @version} = 1. Timestamps use
 * {@code LogstashConfiguration#getDateFormatter}: {@code yyyy-MM-dd'T'HH:mm:ss.SSSZ} unless
 * {@code milliSecondTimestamps} is off, which falls back to {@code yyyy-MM-dd'T'HH:mm:ssZ}. {@code BuildData}'s
 * {@code timestamp} and {@code build} fields are {@code transient}, so Gson does not put them in {@code data}.
 *
 * <p>Transports copied from the plugin's DAOs:
 * <ul>
 *   <li>{@code SyslogDao}: UDP, payload prefixed with {@code " @cee: "}, facility USER (1) and severity
 *       INFORMATIONAL (6) so PRI is 14, app name {@code "jenkins:"} - which the sender writes followed by
 *       {@code ": "}, giving the {@code jenkins:: } the plugin really puts on the wire. RFC 3164 uses
 *       {@code MMM dd HH:mm:ss} in local time; RFC 5424 uses {@code yyyy-MM-dd'T'HH:mm:ss.SSS'Z'} in GMT and
 *       writes {@code -} for the nil PROCID/MSGID/structured data.</li>
 *   <li>{@code RedisDao}: {@code RPUSH key payload}, with {@code AUTH password} first when a password is set;
 *       a reply of 0 or less is an error.</li>
 *   <li>{@code ElasticSearchDao}: HTTP {@code POST} of the payload to the configured URI, content type
 *       {@code application/json; charset=UTF-8}, {@code Authorization: Basic} when a username is set, and any
 *       status outside 2xx is an error.</li>
 * </ul>
 *
 * <p>{@code RabbitMq} is not ported: the plugin delegates the whole AMQP 0-9-1 handshake to {@code amqp-client}, and
 * there is no broker here to prove a hand-rolled client against.
 *
 * <p>Deliberate differences: the step fails when the indexer refuses the payload (the plugin's {@code failBuild}
 * flag is off by default), nothing is retried, the build data comes from step inputs instead of a live {@code Run},
 * {@code timezone} is an explicit input instead of the controller's default zone, and Gson's HTML escaping
 * ({@code \u003d} for {@code =}, ...) is not reproduced - the JSON is semantically identical.
 */
public class LogstashAtom implements AtomTask {

    /** AbstractLogstashIndexerDao#buildPayload */
    static final String SOURCE = "jenkins";
    /** SyslogDao#push: the CEE prefix, with its leading space. */
    static final String CEE_PREFIX = " @cee: ";
    /** SyslogDao: Facility.USER. */
    static final int FACILITY_USER = 1;
    /** SyslogDao: Severity.INFORMATIONAL. */
    static final int SEVERITY_INFORMATIONAL = 6;
    /** SyslogDao: setDefaultAppName("jenkins:"). */
    static final String APP_NAME = "jenkins:";
    /** LogstashConfiguration: yyyy-MM-dd'T'HH:mm:ss.SSSZ, or without the millis when the flag is off. */
    static final DateTimeFormatter TIMESTAMP_MILLIS = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSSZ", Locale.US);
    static final DateTimeFormatter TIMESTAMP_SECONDS = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ssZ", Locale.US);
    /** SyslogMessage: rfc3164DateFormat = MMM dd HH:mm:ss, Locale.US, local time. */
    static final DateTimeFormatter RFC3164_TIMESTAMP = DateTimeFormatter.ofPattern("MMM dd HH:mm:ss", Locale.US);
    /** SyslogMessage: rfc3339DateFormat = yyyy-MM-dd'T'HH:mm:ss.SSS'Z' in GMT. */
    static final DateTimeFormatter RFC5424_TIMESTAMP =
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.US).withZone(java.time.ZoneOffset.UTC);

    /** ElasticSearchDao: ContentType.APPLICATION_JSON.toString(). */
    static final String ES_CONTENT_TYPE = "application/json; charset=UTF-8";

    @Override
    public AtomResult run(AtomContext context) throws Exception {
        String indexer = lower(context, "indexer", "syslog");
        boolean dryRun = context.getBooleanParam("dryRun", false);
        boolean failOnError = context.getBooleanParam("failOnError", true);
        boolean millis = context.getBooleanParam("millisecondTimestamps", true);
        int timeoutSeconds = Math.max(1, Math.min(context.getIntParam("timeoutSeconds", 30), 300));

        if (indexer.equals("rabbitmq")) {
            return AtomResult.error(ErrorType.USER, 40003,
                    "indexer=rabbitmq is not ported: the plugin hands the AMQP 0-9-1 handshake to amqp-client, "
                            + "and an atom cannot prove a hand-written broker client without a broker");
        }
        if (!indexer.equals("syslog") && !indexer.equals("redis") && !indexer.equals("elasticsearch")) {
            return AtomResult.error(ErrorType.USER, 40003,
                    "indexer must be syslog, redis or elasticsearch, not '" + indexer + "'");
        }
        String syslogFormat = lower(context, "syslogFormat", "rfc3164");
        if (indexer.equals("syslog") && !syslogFormat.equals("rfc3164") && !syslogFormat.equals("rfc5424")) {
            return AtomResult.error(ErrorType.USER, 40003,
                    "syslogFormat must be rfc3164 or rfc5424, not '" + syslogFormat + "'");
        }

        ZoneId zone;
        try {
            zone = zone(context);
        } catch (RuntimeException e) {
            return AtomResult.error(ErrorType.USER, 40003, "timezone is not a zone id: " + e.getMessage());
        }

        long nowMs = epochMillis(context, "timestampMs", System.currentTimeMillis(), 40005);
        long buildMs = epochMillis(context, "buildTimestampMs", nowMs, 40005);
        DateTimeFormatter timestampFormat = millis ? TIMESTAMP_MILLIS : TIMESTAMP_SECONDS;

        // ------------------------------------------------------------------ build data
        Map<String, Object> data;
        List<String> lines;
        try {
            data = buildData(context, timestampFormat.withZone(zone), buildMs);
            lines = messageLines(context);
        } catch (IllegalArgumentException e) {
            return AtomResult.error(ErrorType.USER, 40004, e.getMessage());
        }

        // AbstractLogstashIndexerDao#buildPayload, in the order the plugin's JSONObject happens to hold.
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("data", data);
        payload.put("message", lines);
        payload.put("source", SOURCE);
        String jenkinsUrl = expand(context, context.getParam("jenkinsUrl", "")).trim();
        if (!jenkinsUrl.isEmpty()) {
            payload.put("source_host", jenkinsUrl);
        }
        payload.put("@buildTimestamp", timestampFormat.format(Instant.ofEpochMilli(buildMs).atZone(zone)));
        payload.put("@timestamp", timestampFormat.format(Instant.ofEpochMilli(nowMs).atZone(zone)));
        payload.put("@version", 1);
        String json = Json.write(payload);

        // ------------------------------------------------------------------ transport
        String target;
        int port;
        try {
            port = port(context, indexer);
        } catch (IllegalArgumentException e) {
            return AtomResult.error(ErrorType.USER, 40001, e.getMessage());
        }
        String host = expand(context, context.getParam("host", "127.0.0.1")).trim();
        if (indexer.equals("elasticsearch")) {
            URI uri;
            try {
                uri = esUri(context);
            } catch (IllegalArgumentException e) {
                return AtomResult.error(ErrorType.USER, 40001, e.getMessage());
            }
            target = uri.toString();
        } else {
            if (host.isEmpty()) {
                return AtomResult.error(ErrorType.USER, 40001,
                        "host is required for the " + indexer + " indexer");
            }
            target = host + ":" + port;
        }

        if (dryRun) {
            context.log("[logstash] dry run: built " + lines.size() + " log line(s) for " + indexer + " " + target
                    + ", sent nothing");
            return AtomResult.success("dry run: built the payload but sent nothing")
                    .data("indexer", indexer)
                    .data("target", target)
                    .data("lines", String.valueOf(lines.size()))
                    .data("bytes", String.valueOf(json.getBytes(StandardCharsets.UTF_8).length))
                    .data("payload", json);
        }

        try {
            String reply;
            if (indexer.equals("syslog")) {
                reply = sendSyslog(context, json, nowMs, zone, host, port);
            } else if (indexer.equals("redis")) {
                reply = sendRedis(context, json, host, port, timeoutSeconds);
            } else {
                reply = sendElasticSearch(context, json, target, timeoutSeconds);
            }
            context.log("[logstash] sent " + lines.size() + " log line(s) to " + indexer + " " + target
                    + " (" + json.getBytes(StandardCharsets.UTF_8).length + " bytes)");
            return AtomResult.success("sent the build payload to " + indexer + " " + target)
                    .data("indexer", indexer)
                    .data("target", target)
                    .data("lines", String.valueOf(lines.size()))
                    .data("bytes", String.valueOf(json.getBytes(StandardCharsets.UTF_8).length))
                    .data("reply", reply)
                    .data("payload", json);
        } catch (IOException e) {
            String message = "could not send to " + indexer + " " + target + ": " + e.getMessage();
            if (!failOnError) {
                context.log("[logstash] " + message + " (failOnError=false, continuing)");
                return AtomResult.success(message)
                        .data("indexer", indexer)
                        .data("target", target)
                        .data("lines", String.valueOf(lines.size()))
                        .data("bytes", String.valueOf(json.getBytes(StandardCharsets.UTF_8).length))
                        .data("reply", "")
                        .data("payload", json);
            }
            return AtomResult.error(ErrorType.THIRD_PART, 40010, message)
                    .data("indexer", indexer)
                    .data("target", target)
                    .data("lines", String.valueOf(lines.size()))
                    .data("bytes", String.valueOf(json.getBytes(StandardCharsets.UTF_8).length))
                    .data("payload", json);
        }
    }

    // ------------------------------------------------------------------ the data object

    /**
     * BuildData as Gson writes it: declaration order, nulls dropped (Gson has no serializeNulls), and the
     * transient {@code timestamp}/{@code build} fields absent. {@code sensitiveBuildVariables} is only set on the
     * freestyle path, so it stays out.
     */
    private Map<String, Object> buildData(AtomContext context, DateTimeFormatter format, long buildMs) {
        String projectName = expand(context, context.getParam("projectName", "${JOB_NAME}")).trim();
        if (projectName.isEmpty() || projectName.contains("${")) {
            throw new IllegalArgumentException("projectName is required: the plugin uses run.getParent().getName()");
        }
        int buildNum = integer(context, "buildNumber", "${BUILD_NUMBER}", -1, 40006);
        if (buildNum < 0) {
            throw new IllegalArgumentException("buildNumber must be a non-negative integer");
        }
        String fullProjectName = value(context, "fullProjectName", projectName);
        String displayName = value(context, "displayName", "#" + buildNum);
        String fullDisplayName = value(context, "fullDisplayName", fullProjectName + " " + displayName);

        String host = value(context, "buildHost", value(context, "node", "master"));
        String label = value(context, "buildLabel", value(context, "label", "master"));
        if (host.isEmpty()) {
            host = "master";
        }
        if (label.isEmpty()) {
            label = "master";
        }

        Map<String, Object> data = new LinkedHashMap<>();
        data.put("id", value(context, "buildId", String.valueOf(buildNum)));
        String result = expand(context, context.getParam("result", "${BUILD_STATUS}")).trim().toUpperCase(Locale.ROOT);
        if (!result.isEmpty() && !result.contains("${")) {
            data.put("result", result);
        }
        data.put("projectName", projectName);
        data.put("fullProjectName", fullProjectName);
        data.put("displayName", displayName);
        data.put("fullDisplayName", fullDisplayName);
        data.put("description", expand(context, context.getParam("description", "")));
        data.put("url", expand(context, context.getParam("buildUrl", "")));
        data.put("buildHost", host);
        data.put("buildLabel", label);
        String stageName = expand(context, context.getParam("stageName", "")).trim();
        if (!stageName.isEmpty()) {
            data.put("stageName", stageName);
        }
        String agentName = expand(context, context.getParam("agentName", "")).trim();
        if (!agentName.isEmpty()) {
            data.put("agentName", agentName);
        }
        data.put("buildNum", buildNum);
        long duration = epochMillis(context, "buildDurationMs", 0L, 40006);
        if (duration < 0) {
            throw new IllegalArgumentException("buildDurationMs must be a non-negative number of milliseconds");
        }
        // initData: currentTime - build.getStartTimeInMillis()
        data.put("buildDuration", duration > 0 ? duration : Math.max(0L, System.currentTimeMillis() - buildMs));
        data.put("rootProjectName", value(context, "rootProjectName", projectName));
        data.put("rootFullProjectName", value(context, "rootFullProjectName", fullProjectName));
        data.put("rootProjectDisplayName", value(context, "rootProjectDisplayName", displayName));
        data.put("rootBuildNum", integer(context, "rootBuildNum", String.valueOf(buildNum), buildNum, 40006));
        data.put("buildVariables", variables(context));
        Map<String, Object> tests = testResults(context);
        if (!tests.isEmpty()) {
            data.put("testResults", tests);
        }
        return data;
    }

    /** TestData: total/skip/fail, passCount = total - skip - fail, then the failed names and their details. */
    private Map<String, Object> testResults(AtomContext context) {
        Map<String, Object> tests = new LinkedHashMap<>();
        if (expand(context, context.getParam("testsTotal", "")).trim().isEmpty()) {
            return tests;
        }
        int total = integer(context, "testsTotal", "", 0, 40008);
        int skipped = integer(context, "testsSkipped", "", 0, 40008);
        int failed = integer(context, "testsFailed", "", 0, 40008);
        if (total < 0 || skipped < 0 || failed < 0) {
            throw new IllegalArgumentException("testsTotal/testsSkipped/testsFailed must be non-negative integers");
        }
        tests.put("totalCount", total);
        tests.put("skipCount", skipped);
        tests.put("failCount", failed);
        tests.put("passCount", total - skipped - failed);
        List<Map<String, Object>> detailed = new ArrayList<>();
        List<String> names = new ArrayList<>();
        String text = expand(context, context.getParam("failedTests", ""));
        for (String line : text.split("\r?\n")) {
            if (line.trim().isEmpty()) {
                continue;
            }
            int bar = line.indexOf('|');
            String name = (bar < 0 ? line : line.substring(0, bar)).trim();
            if (name.isEmpty()) {
                continue;
            }
            Map<String, Object> item = new LinkedHashMap<>();
            item.put("fullName", name);
            if (bar >= 0) {
                item.put("errorDetails", line.substring(bar + 1));
            }
            detailed.add(item);
            names.add(name);
        }
        tests.put("failedTestsWithErrorDetail", detailed);
        tests.put("failedTests", names);
        return tests;
    }

    /** The build variables map: key=value lines, with the named ones dropped (the freestyle path's masking). */
    private Map<String, Object> variables(AtomContext context) {
        Map<String, Object> values = new LinkedHashMap<>();
        String text = expand(context, context.getParam("buildVariables", ""));
        if (text == null || text.isEmpty()) {
            return values;
        }
        List<String> masked = new ArrayList<>();
        for (String name : expand(context, context.getParam("maskedVariables", "")).split(",")) {
            if (!name.trim().isEmpty()) {
                masked.add(name.trim());
            }
        }
        for (String line : text.split("\r?\n")) {
            String row = line.trim();
            if (row.isEmpty()) {
                continue;
            }
            int eq = row.indexOf('=');
            if (eq <= 0) {
                throw new IllegalArgumentException("buildVariables must be key=value lines, got: " + row);
            }
            String key = row.substring(0, eq).trim();
            if (!masked.contains(key)) {
                values.put(key, row.substring(eq + 1));
            }
        }
        return values;
    }

    /**
     * LogstashNotifier#perform calls {@code build.getLog(maxLines)}: the most recent lines, at most maxLines, and an
     * empty list for 0 (Run#getLog returns early for 0). Negative means the whole log.
     */
    private List<String> messageLines(AtomContext context) {
        int maxLines = integer(context, "maxLines", "100", 100, 40007);
        String text = expand(context, context.getParam("message", ""));
        List<String> lines = new ArrayList<>();
        if (text != null && !text.isEmpty()) {
            String normalised = text.endsWith("\r\n") ? text.substring(0, text.length() - 2)
                    : text.endsWith("\n") ? text.substring(0, text.length() - 1) : text;
            for (String line : normalised.split("\r?\n", -1)) {
                lines.add(line);
            }
        }
        // maxLines == 0 falls out of the window below and sends nothing, like Run#getLog(0)
        if (maxLines < 0 || lines.size() <= maxLines) {
            return lines;
        }
        return new ArrayList<>(lines.subList(lines.size() - maxLines, lines.size()));
    }

    // ------------------------------------------------------------------ transports

    /** SyslogDao#push + SyslogMessage#toRfc3164SyslogMessage / toRfc5424SyslogMessage, over UDP. */
    private String sendSyslog(AtomContext context, String json, long nowMs, ZoneId zone, String host, int port)
            throws IOException {
        String format = lower(context, "syslogFormat", "rfc3164");
        String message = CEE_PREFIX + json;
        int pri = FACILITY_USER * 8 + SEVERITY_INFORMATIONAL;
        ZonedDateTime stamp = Instant.ofEpochMilli(nowMs).atZone(zone);
        StringBuilder sb = new StringBuilder();
        sb.append('<').append(pri).append('>');
        if (format.equals("rfc3164")) {
            // <PRI>MMM dd HH:mm:ss HOST APPNAME: msg
            sb.append(RFC3164_TIMESTAMP.format(stamp)).append(' ');
            sb.append(host).append(' ');
            sb.append(APP_NAME).append(": ").append(message);
        } else {
            // <PRI>1 TIMESTAMP HOST APPNAME PROCID MSGID SD msg, nil values as '-'
            sb.append('1').append(' ');
            sb.append(RFC5424_TIMESTAMP.format(stamp)).append(' ');
            sb.append(host).append(' ');
            sb.append(APP_NAME).append(' ');
            sb.append('-').append(' ').append('-').append(' ').append('-').append(' ');
            sb.append(message);
        }
        byte[] bytes = sb.toString().getBytes(StandardCharsets.UTF_8);
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.send(new DatagramPacket(bytes, bytes.length, InetAddress.getByName(host), port));
        }
        return "udp " + bytes.length + " bytes";
    }

    /** RedisDao#push: AUTH when a password is set, then RPUSH key data; a reply of 0 or less is a failure. */
    private String sendRedis(AtomContext context, String json, String host, int port, int timeoutSeconds)
            throws IOException {
        String key = expand(context, context.getParam("redisKey", "logstash")).trim();
        if (key.isEmpty()) {
            throw new IOException("redisKey is required: the plugin rejects a blank Redis key");
        }
        String password = firstNonEmpty(context.getSecret("redisPassword"),
                expand(context, context.getParam("redisPassword", "")));
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), timeoutSeconds * 1000);
            socket.setSoTimeout(timeoutSeconds * 1000);
            OutputStream out = socket.getOutputStream();
            InputStream in = socket.getInputStream();
            if (!password.isEmpty()) {
                command(out, "AUTH", password);
                String auth = reply(in);
                if (auth.startsWith("-")) {
                    throw new IOException("redis refused AUTH: " + auth.substring(1));
                }
            }
            command(out, "RPUSH", key, json);
            String pushed = reply(in);
            if (pushed.startsWith("-")) {
                throw new IOException("redis refused RPUSH: " + pushed.substring(1));
            }
            long length;
            try {
                length = Long.parseLong(pushed.substring(1).trim());
            } catch (RuntimeException e) {
                throw new IOException("redis answered RPUSH with '" + pushed.trim() + "', not an integer");
            }
            if (length <= 0) {
                throw new IOException("Failed to push results: RPUSH returned " + length);
            }
            return "rpush " + length;
        }
    }

    /** RESP2 arrays, the way Jedis sends them: bulk strings, one command per connection write. */
    private static void command(OutputStream out, String... args) throws IOException {
        StringBuilder sb = new StringBuilder();
        sb.append('*').append(args.length).append("\r\n");
        for (String arg : args) {
            byte[] bytes = arg.getBytes(StandardCharsets.UTF_8);
            sb.append('$').append(bytes.length).append("\r\n");
            out.write(sb.toString().getBytes(StandardCharsets.UTF_8));
            out.write(bytes);
            out.write('\r');
            out.write('\n');
            sb.setLength(0);
        }
        out.flush();
    }

    private static String reply(InputStream in) throws IOException {
        StringBuilder line = new StringBuilder();
        int b;
        while ((b = in.read()) != -1) {
            if (b == '\r') {
                continue;
            }
            if (b == '\n') {
                break;
            }
            line.append((char) b);
        }
        if (b == -1) {
            throw new IOException("redis closed the connection without a reply");
        }
        return line.toString();
    }

    /** ElasticSearchDao#push: POST the payload, 2xx is success, and a non-2xx carries the status and body. */
    private String sendElasticSearch(AtomContext context, String json, String target, int timeoutSeconds)
            throws IOException {
        String mimeType = expand(context, context.getParam("mimeType", "")).trim();
        if (mimeType.isEmpty()) {
            mimeType = ES_CONTENT_TYPE;
        }
        String username = expand(context, context.getParam("esUsername", "")).trim();
        String password = firstNonEmpty(context.getSecret("esPassword"),
                expand(context, context.getParam("esPassword", "")));
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(target))
                .timeout(Duration.ofSeconds(timeoutSeconds))
                .header("Content-Type", mimeType)
                .POST(HttpRequest.BodyPublishers.ofString(json, StandardCharsets.UTF_8));
        if (!username.isEmpty()) {
            String token = Base64.getEncoder()
                    .encodeToString((username + ":" + password).getBytes(StandardCharsets.UTF_8));
            request.header("Authorization", "Basic " + token);
        }
        HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(timeoutSeconds)).build();
        HttpResponse<String> response;
        try {
            response = client.send(request.build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("interrupted while posting to " + target);
        }
        int status = response.statusCode();
        String body = response.body() == null ? "" : response.body();
        if (status < 200 || status >= 300) {
            throw new IOException("HTTP error code: " + status + "\nURI: " + target + "\nRESPONSE: "
                    + abbreviate(body));
        }
        return "http " + status;
    }

    // ------------------------------------------------------------------ input helpers

    private static ZoneId zone(AtomContext context) {
        String name = expand(context, context.getParam("timezone", "")).trim();
        if (name.isEmpty()) {
            return ZoneId.systemDefault();
        }
        return ZoneId.of(name);
    }

    private static URI esUri(AtomContext context) {
        String raw = expand(context, context.getParam("esUri", "")).trim();
        if (raw.isEmpty()) {
            throw new IllegalArgumentException("esUri is required for indexer=elasticsearch, e.g. http://localhost:9200/logstash");
        }
        URI uri;
        try {
            uri = URI.create(raw);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("esUri is not a URI: " + raw);
        }
        if (uri.getScheme() == null || (!uri.getScheme().equals("http") && !uri.getScheme().equals("https"))
                || uri.getHost() == null) {
            throw new IllegalArgumentException("esUri must be an http(s) URL with a host, not '" + raw + "'");
        }
        return uri;
    }

    private static int port(AtomContext context, String indexer) {
        String raw = expand(context, context.getParam("port", "")).trim();
        if (raw.isEmpty()) {
            return indexer.equals("redis") ? 6379 : 519;
        }
        int value;
        try {
            value = Integer.parseInt(raw);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException("port must be an integer, not '" + raw + "'");
        }
        if (value < 1 || value > 65535) {
            throw new IllegalArgumentException("port must be between 1 and 65535, not " + value);
        }
        return value;
    }

    private static int integer(AtomContext context, String name, String fallbackRaw, int fallback, int code) {
        String raw = expand(context, context.getParam(name, fallbackRaw));
        if (raw == null || raw.trim().isEmpty()) {
            return fallback;
        }
        try {
            return Integer.parseInt(raw.trim());
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(name + " must be an integer, not '" + raw + "'");
        }
    }

    private static long epochMillis(AtomContext context, String name, long fallback, int code) {
        String raw = expand(context, context.getParam(name, ""));
        if (raw == null || raw.trim().isEmpty()) {
            return fallback;
        }
        try {
            long value = Long.parseLong(raw.trim());
            if (value < 0) {
                throw new IllegalArgumentException(name + " must not be negative, got " + value);
            }
            return value;
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(name + " must be epoch milliseconds, not '" + raw + "'");
        }
    }

    private static String lower(AtomContext context, String name, String fallback) {
        return expand(context, context.getParam(name, fallback)).trim().toLowerCase(Locale.ROOT);
    }

    private static String value(AtomContext context, String name, String fallback) {
        String raw = expand(context, context.getParam(name, ""));
        String trimmed = raw == null ? "" : raw.trim();
        return trimmed.isEmpty() ? fallback : trimmed;
    }

    private static String firstNonEmpty(String a, String b) {
        if (a != null && !a.isEmpty()) {
            return a;
        }
        return b == null ? "" : b;
    }

    static String expand(AtomContext context, String value) {
        if (value == null || value.indexOf("${") < 0) {
            return value == null ? "" : value;
        }
        Matcher matcher = Pattern.compile("\\$\\{([A-Za-z_][A-Za-z0-9_]*)}").matcher(value);
        StringBuilder sb = new StringBuilder();
        while (matcher.find()) {
            String name = matcher.group(1);
            String replacement = context.getParam(name);
            if (replacement == null) {
                replacement = System.getenv(name);
            }
            matcher.appendReplacement(sb, Matcher.quoteReplacement(replacement == null ? matcher.group() : replacement));
        }
        matcher.appendTail(sb);
        return sb.toString();
    }

    private static String abbreviate(String text) {
        String oneLine = text.replace('\n', ' ').replace('\r', ' ').trim();
        return oneLine.length() <= 400 ? oneLine : oneLine.substring(0, 400) + "...";
    }
}
