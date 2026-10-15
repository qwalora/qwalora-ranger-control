# Board 2 M4.2 — live operational SOC validation report

Bounded live validation against the **private** OpenSearch cluster
(`opensearch.railway.internal:9200`), using only the synthetic `board2-test`
identity, on the existing Railway `siem-validator` service (Dockerfile, restart
policy NEVER, one-shot). No new infrastructure. Candidate access and act-as stayed
disabled; the enterprise grader stayed shadow-only; `PASS_BAR = 95.0` untouched; the
25-candidate workload was not activated.

Reproduce: set `RANGER_VALIDATE_MODE=m4stream` on `siem-validator` (optional
`M4_RUN_WINDOW_S`, `M4_TICKS`, `M4_DEADLINE_S`) and read the deploy logs between
`===RANGER_VALIDATION_JSON_BEGIN===` / `===END===`. Teardown + verify-stop:
`RANGER_VALIDATE_MODE=m4stop`.

## Acceptance chain status

| Stage | Result |
|---|---|
| Continuous telemetry (multi-interval) | **PASS** |
| OpenSearch ingestion (isolated op index) | **PASS** |
| Native Security Analytics detector execution | **PASS** (detector created + running on schedule) |
| Finding / alert | **NOT YET** (detector executes, but the pre-packaged rule did not match the synthetic event under current field mappings) |
| Authorized SOC investigation | **PASS** |

`fully_demonstrated: false` — the single remaining hop is a genuine **finding/alert**.
Everything else is validated live. Nothing below is faked; the finding gap is a
documented limitation with a concrete remediation.

## What passed, with evidence

- **Continuous ingestion across scheduled worker ticks** — 5 ticks + a drain tick,
  `indexed_total 7/7`, `multi_tick_ingestion: true`, watermark persisted in a
  cluster state doc (`ranger-op-state`). Not a one-shot bulk import.
- **Isolated operational index** — `ranger-op-pilot-board2-test-b2`, distinct from
  the qualification index `ranger-pilot-board2-test-b2`; the qualification plane was
  never touched.
- **Field correctness** — sampled docs all carry `@timestamp` (current era),
  `event.ingested`, identity fields (`user.name`/`source.ip`), mapped security
  fields (`winlog.event_id`, `dns.question.name`), and `ranger.plane=operational`.
- **Synthetic labeling** — every operational event has `data.synthetic=true`; org is
  "Valyria Financial Group (fictional, synthetic lab data)".
- **Genuine Security Analytics** — field mapping applied (`acknowledged:true`);
  pre-packaged **windows** rule discovered keyed on EventID 4728
  (`rule_id 9aa01d62-7667-4d3b-acb8-8cb5103e2014`, from 1,580 windows rules);
  **native detectors created and executing** on a 1-minute schedule
  (`detector_id 6xVEQaEBbaZn28UU4Paf`, and `IRVNQaEBbaZn28UU4_et` on a later run),
  registered in `.opensearch-sap-detectors-config`; the findings API was polled live
  (HTTP 200) every 20 s for the whole bounded window.
- **Trace (to the detector)** — the 4728 trigger event was indexed
  (`event_uid e7f7b0330d9326ac8923`; a fresh post-detector event
  `m4-live-4728-204306` was also indexed in the detector's forward window); the
  authorized investigation query `{"term":{"winlog.event_id":4728}}` run **as the
  candidate** returned 200.
- **Candidate isolation** — own op index readable; cross-candidate read 403;
  `.opendistro_security` and the security API denied. (No protected-truth index
  exists candidate-side; truth lives only in the Ranger backend.)
- **SOC admin oversight without broad security admin** — reads the operational index
  and findings; denied the security index; cannot create users.
- **Recovery (live)** — watermark persisted + read back by a fresh store; replay of
  the full window produced 7 `create` conflicts and 0 new docs (idempotent); a
  mapping-violating doc was dead-lettered while the valid doc indexed. (Live 429
  backpressure was not force-induced on a healthy cluster; it is covered by the
  offline suite `test_telemetry_stream.py`.)
- **Measured performance (functional profile)** — ingest ~0.14 EPS; event→ingest
  delay p50 0 s / max ≤6 s; query latency ~10–18 ms; op index ~42–47 KB for the run;
  OpenSearch heap 17–70% of a 1 GB heap at this rate; ~9.7 GB disk free. Cross-check
  Railway service metrics for the opensearch service over the window.
- **Bounded + verified stop** — each run deletes its detector and disposable
  identities; the `m4stop` teardown then verified `remaining_detectors: 0` and
  `unattended_workload_cleared: true`. No SA workload runs unattended.

## The one gap: a genuine finding did not fire

The detector is genuinely created and executing, but produced **0 findings** within
the deadline, including for a fresh current-timestamp 4728 event placed in its
forward scan window. Root cause: the chosen pre-packaged Sigma rule's selection is
not satisfied by the synthetic event under the current Security Analytics field
mappings (only `winlog.event_id → EventID` was mapped). A separate issue: the SA
**custom** rule create returns `500 SearchPhaseExecutionException` on this build,
so the guaranteed-match custom rule (EventID:4728 only) was not usable.

Both are tractable tuning items, not environment failures — SA is fully initialized
(2,221 windows pre-packaged rules; `.opensearch-sap-pre-packaged-rules-config` holds
22,992 docs; plugin present).

## Recommended next step (for a focused follow-up, on your approval)

1. Apply the **full** windows field mappings from the detector's
   `get_mappings_view` (map every required alias, not just EventID) so a
   pre-packaged rule's fields resolve against the synthetic event; or
2. Resolve the custom-rule `500` (likely a rules-index/log-type bootstrap quirk) and
   drive the detector with a minimal custom rule (`EventID: 4728`) that is guaranteed
   to match the enriched event, producing a finding and, via the detector trigger, an
   alert; then re-run the trace to a real `finding_id` and `alert_id`.

Either path is a small, bounded iteration. Until then, M4.2 has demonstrated the
operational chain through genuine native detector execution, with the finding/alert
hop explicitly outstanding.

## Release posture during this milestone (unchanged)

Synthetic identity only; general candidate access and act-as disabled; enterprise
grader shadow-only; 95% bar preserved; no 25-candidate workload; no new paid
infrastructure; time-bounded run with an explicit, verified stop.
