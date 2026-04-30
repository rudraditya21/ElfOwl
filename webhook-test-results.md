# Webhook Pusher — Test Results

**Branch:** fix/tls-hardening-ja3-webhook  
**Date:** 2026-04-30  
**Go version:** see go.mod  

---

## Test Plan Coverage

| # | Test Plan Item | Coverage | Status |
|---|---|---|---|
| 1 | No-K8s mode: all 6 event types received by listener | `TestWebhookPusherAllSixEventTypes` | PASS |
| 1a | Fields populated: ClusterID, NodeName, Timestamp, Workload.PodName/Namespace/Image | `TestWebhookPusherEventFieldsPopulated` | PASS |
| 2 | K8s mode: pod_name, namespace, image from live alpine pod | Manual — requires live VM+K8s environment | PENDING |
| 3 | `go build ./...` and `go test ./pkg/agent/...` pass clean | CI / local run | PASS |
| 4 | `start-agent.sh --enable-webhook` logs pusher initialized | Manual — requires VM | PENDING |
| 5 | `webhook.enabled=true` + empty `target_url` rejected at startup | `TestValidateRejectsEnabledWebhookWithEmptyURL` | PASS |
| 6 | `node_name` in events matches actual hostname, not literal `${HOSTNAME}` | `TestExpandSentinelVarsHostname` | PASS |

---

## Unit Test Results

```
go test -v -count=1 ./pkg/agent/... -run "TestWebhook|TestValidate|TestExpand|TestRedact"
```

| Test | Description | Result |
|---|---|---|
| `TestWebhookPusherAllSixEventTypes` | process_execution, network_connection, file_access, dns_query, capability_usage, tls_client_hello all delivered to httptest.Server | PASS |
| `TestWebhookPusherEventFieldsPopulated` | ClusterID, NodeName, Timestamp, Workload.PodName/Namespace/Image set correctly | PASS |
| `TestWebhookPusherStartIdempotent` | Calling Start() three times delivers only 1 event — no duplicate goroutines | PASS |
| `TestWebhookPusherStopIdempotent` | Calling Stop() twice does not panic | PASS |
| `TestWebhookPusherZeroFlushIntervalClamped` | FlushInterval=0 and Timeout=0 clamped to defaults without panic | PASS |
| `TestWebhookPusherDrainOnStop` | 5 events sent, ticker disabled — Stop() drains all 5 before returning | PASS |
| `TestWebhookPusherBatchSizeFlush` | BatchSize=3, 3 events sent — flush fires immediately without waiting for ticker | PASS |
| `TestValidateRejectsEnabledWebhookWithEmptyURL` | Validate() returns error when enabled=true and target_url="" | PASS |
| `TestValidateAcceptsEnabledWebhookWithURL` | Validate() passes when enabled=true and target_url is set | PASS |
| `TestValidateRejectsNegativeBatchSize` | Validate() returns error for batch_size=-1 | PASS |
| `TestValidateRejectsNegativeFlushInterval` | Validate() returns error for flush_interval=-1 | PASS |
| `TestExpandSentinelVarsHostname` | `${HOSTNAME}` and `$HOSTNAME` expanded to actual value; not left as literal string | PASS |
| `TestExpandSentinelVarsOWLPrefix` | `${OWL_CLUSTER_ID}` expanded; `${SECRET_KEY}` left unexpanded | PASS |
| `TestWebhookPusherViolationsForwarded` | Violations array attached to event and delivered with correct ControlID | PASS |
| `TestWebhookPusherHandles4xx` | 422 response handled without panic; subsequent POST succeeds (body drain enables connection reuse) | PASS |
| `TestRedactHeaders` | Authorization/X-Api-Key/X-Auth-Token redacted to `[redacted]`; Content-Type/X-Request-ID unchanged; original map not mutated | PASS |

**Total: 16/16 PASS**

Full suite:

```
go test -count=1 ./pkg/...
```

All packages pass clean.

---

## Issues Verified by Tests

| Issue | Test |
|---|---|
| #1 Stop() double-close panic | `TestWebhookPusherStopIdempotent` |
| #2 Start() duplicate goroutine | `TestWebhookPusherStartIdempotent` |
| #3 NewTicker(0) / no HTTP deadline | `TestWebhookPusherZeroFlushIntervalClamped` |
| #5 Body not drained on error | `TestWebhookPusherHandles4xx` |
| #6 Drain-on-Stop guarantee | `TestWebhookPusherDrainOnStop` |
| #7 Auth token log leak | `TestRedactHeaders` |
| #8 Blanket os.ExpandEnv | `TestExpandSentinelVarsHostname`, `TestExpandSentinelVarsOWLPrefix` |
| #14 Validation not in Validate() | `TestValidateRejectsNegativeBatchSize`, `TestValidateRejectsNegativeFlushInterval` |
| Test Plan item 5 | `TestValidateRejectsEnabledWebhookWithEmptyURL` |
| Test Plan item 6 | `TestExpandSentinelVarsHostname` |

---

## Pending (requires live environment)

### Test Plan item 2 — K8s mode with live alpine pod

Run the agent against a cluster with an alpine pod running:

```bash
./scripts/start-agent.sh \
  --kubeconfig /path/to/kubeconfig \
  --enable-webhook \
  --webhook-url http://<listener>:8888/events \
  --log-level debug
```

Verify in received events:
- `metadata.workload.pod_name` matches the alpine pod name
- `metadata.workload.namespace` matches the deployment namespace  
- `metadata.workload.image` contains `alpine`

### Test Plan item 4 — pusher initialized log line

```bash
./scripts/start-agent.sh --no-k8s --enable-webhook --webhook-url http://127.0.0.1:8888/events
```

Expected in `/var/log/elf-owl/agent.log`:

```
{"level":"info", ... "msg":"webhook pusher started", "target_url":"http://127.0.0.1:8888/events"}
```
