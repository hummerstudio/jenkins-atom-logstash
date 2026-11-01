# logstash

Port of the `logstash` plugin (org.jenkins-ci.plugins:logstash 2.5.0, ~2.8k installs) as one atom:
`com.jenkinschina.atom.sdk.AtomTask`, packaged by `AtomRunner`.

The plugin's job is one payload per build: `AbstractLogstashIndexerDao#buildPayload` wraps the Gson-serialised
`BuildData` plus the build's log lines, and a DAO pushes it at the configured indexer. This atom does the same for
one build, with the payload and the transports copied from the plugin's own code.

## The payload

```
{
  "data":   { ...BuildData... },   // Gson on the POJO: declaration order, nulls dropped
  "message": ["line one", ...],    // Run#getLog(maxLines): the last maxLines lines, [] for 0
  "source": "jenkins",
  "source_host": "<jenkins root url>",   // dropped when the root URL is null
  "@buildTimestamp": "2025-11-01T20:26:40.000+0800",
  "@timestamp":      "2025-11-01T20:26:45.000+0800",
  "@version": 1
}
```

`LogstashConfiguration#getDateFormatter` is `yyyy-MM-dd'T'HH:mm:ss.SSSZ`, or `yyyy-MM-dd'T'HH:mm:ssZ` when
`milliSecondTimestamps` is off (`millisecondTimestamps=false` here). `BuildData`'s `timestamp` and `build` fields are
`transient`, so they never appear inside `data`; the build time only travels as `@buildTimestamp`.

`data` follows the POJO: `id`, `result`, `projectName`, `fullProjectName`, `displayName`, `fullDisplayName`,
`description`, `url`, `buildHost`, `buildLabel`, `stageName`, `agentName`, `buildNum`, `buildDuration` (ms),
`rootProjectName`, `rootFullProjectName`, `rootProjectDisplayName`, `rootBuildNum`, `buildVariables`, `testResults`.
`result` is absent while a build has no result, `stageName`/`agentName` only exist on the pipeline path,
`buildHost`/`buildLabel` fall back to `master` the way `BuildData#initData` does, and `testResults` is written only
when tests are passed in - with `passCount = totalCount - skipCount - failCount` and both the failed names and the
`fullName`/`errorDetails` pairs.

## The transports

- **syslog** (`SyslogDao`, UDP): payload prefixed with `" @cee: "`, facility USER (1) and severity INFORMATIONAL (6)
  so PRI is 14, app name `jenkins:` - which `AbstractSyslogMessageSender` writes followed by `": "`, so the wire really
  says `jenkins::  @cee: `. RFC 3164 is `<14>MMM dd HH:mm:ss HOST jenkins::  @cee: {...}` in local time; RFC 5424 is
  `<14>1 <yyyy-MM-dd'T'HH:mm:ss.SSS'Z'> HOST jenkins: - - -  @cee: {...}` with GMT and `-` for the nil PROCID, MSGID
  and structured data.
- **redis** (`RedisDao`): `AUTH password` first when a password is set, then `RPUSH key payload`; a reply of 0 or less
  is `Failed to push results`.
- **elasticsearch** (`ElasticSearchDao`): `POST` of the payload to the configured URI, `Content-Type`
  `application/json; charset=UTF-8` (or `mimeType`), `Authorization: Basic` when a username is set, and anything
  outside 2xx fails with `HTTP error code: ...`.

**rabbitmq is not ported.** The plugin hands the entire AMQP 0-9-1 handshake to `amqp-client`; there is no broker here,
so a hand-written client could not be proven - the atom refuses the option and says why (40003).

## Deliberate differences

- A refused payload fails the step by default (`failOnError=true`). The plugin only fails when the job property's
  `failBuild` is ticked; by default it writes an error to the build log and carries on.
- Nothing is retried, and the payload is sent once instead of through the plugin's per-build writer.
- The build data comes from step inputs instead of a live `Run`, and `timezone` is an explicit input rather than the
  controller's default zone (a step cannot read it).
- `sensitiveBuildVariables` is never written: the plugin only sets it on the freestyle path, which a step is not.
- Gson's HTML escaping (`\u003d` for `=`, `\u003c` for `<`) is not reproduced; the JSON is semantically identical.
- Elasticsearch `connectTimeout`/`socketTimeout` collapse into `timeoutSeconds`, and a custom keystore is not
  supported (the atom uses `java.net.http` and the JVM's trust store).

## Checks

`tools/check.py` runs the atom the way the runner does and compares the bytes a fake indexer received against a
recomputation of the plugin's rules: the payload object (field order, types, nulls, transients), the syslog frame for
both RFCs and both timestamp formats, the RESP command sequence, and the HTTP request. Failures are asserted too
(refused push, `-ERR`, zero-length push, HTTP 500, unreachable port, `failOnError=false`, dry run, input validation).

`tools/mutations.py` plants 24 bugs one at a time and requires the suite to go red for each.

```
./tools/smoke.sh --mutations
```
