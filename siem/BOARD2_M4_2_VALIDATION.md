# Board 2 M4.2 — live operational SOC validation report

Bounded live validation against the **private** OpenSearch cluster
(`opensearch.railway.internal:9200`), using only the synthetic `board2-test`
identity, on the existing Railway `siem-validator` service (Dockerfile, restart
policy NEVER, one-shot). No new infrastructure. Candidate access and act-as stayed
disabled; the enterprise grader stayed shadow-only; `PASS_BAR = 95.0` untouched; the
25-candidate workload was not activated.

Reproduce: set `RANGER_VALIDATE_MODE=m4stream` on `siem-validator` (optional
`M4_RUN_WINDOW_S`, `M4_TICKS`, `M4_DEADLINE_S`, `M4_RULE_ID`) and read the deploy
logs between `===RANGER_VALIDATION_JSON_BEGIN===` / `===END===`. Diagnosis:
`RANGER_VALIDATE_MODE=m4diag`. Teardown + verify-stop: `RANGER_VALIDATE_MODE=m4stop`.

## Acceptance chain status — COMPLETE

| Stage | Result |
|---|---|
| Continuous telemetry (multi-interval) | **PASS** |
| OpenSearch ingestion (isolated op index) | **PASS** |
| Native Security Analytics detector execution | **PASS** |
| Genuine finding + alert | **PASS** |
| Authorized SOC investigation | **PASS** |

`acceptance_chain.fully_demonstrated: true`. The full native chain was demonstrated
with actual OpenSearch Security Analytics results — a genuine finding and a genuine
trigger alert, not Ranger's offline `detection.py`.

## Genuine end-to-end chain (real IDs)

```
indexed event  m4-live-sllauncher-211634   (ranger-op-pilot-board2-test-b2)
   -> native SA detector  jxVsQaEBbaZn28UUivf2  (log type: windows, 1-min schedule)
   -> pre-packaged rule    9aa01d62-7667-4d3b-acb8-8cb5103e2014
                           "Emissary Panda Malware SLLauncher" (process_creation)
                           query: (winlog.event_data.ParentImage: *\sllauncher.exe)
                                  AND (winlog.event_data.Image: *\svchost.exe)
   -> FINDING  206abfea-aa1e-423e-b380-0d92024946ff
               detectorId jxVsQaEBbaZn28UUivf2, rule 9aa01d62,
               associated_doc_ids [m4-live-sllauncher-211634]
   -> ALERT    50ad9f32-1a5f-4aa7-9d48-225dd45475e9
               trigger "dll-sideload", severity 1, state ACTIVE,
               finding_ids [206abfea-aa1e-423e-b380-0d92024946ff]
   -> authorized investigation (as board2-test, JWT):
               {"wildcard":{"winlog.event_data.ParentImage":"*\\sllauncher.exe"}}  -> 200
```

SA execution left real plugin artifacts: `.opensearch-sap-windows-detectors-queries-000001`
(2 docs), `.opensearch-sap-windows-alerts-history-2026.10.15-1` (1 doc),
`.opensearch-sap-detectors-config`. Findings vs alerts are reported separately: the
finding is the rule match; the alert is raised by the detector's `dll-sideload`
trigger and carries the finding id. (A benign `NoOp trigger` ERROR alert row was
also observed and recorded honestly, not counted as the detection alert.)

## Diagnosis that unblocked the finding (m4diag)

The first finding attempts produced 0 findings. The `m4diag` introspection
retrieved the real rule and mappings via supported APIs and showed the exact cause:

- The rule being used, `9aa01d62`, is **not** a 4728 rule — it is a Windows
  **process_creation** rule (Emissary Panda SLLauncher) keyed on
  `ParentImage endswith \sllauncher.exe` AND `Image endswith \svchost.exe`. EventID
  alone was never sufficient; the synthetic 4728 event had none of those fields.
- The op index did not carry the `winlog.event_data.*` fields the windows rules key
  on, and those that were added dynamically would have been analyzed `text`, on
  which the rule's wildcard/endswith selection would not match.

Correction (telemetry + mapping, never the rule): the privileged-identity incident
now emits a realistic DLL side-loading (T1574.002) Sysmon process-creation event
(`sllauncher.exe -> svchost.exe`); the op index maps `winlog.event_data.*` as
`keyword`; SA auto-maps the windows log type; and a fresh matching event is injected
in the detector's forward scan window. The rule was not modified.

## Other stages, with evidence

- **Continuous ingestion across scheduled worker ticks** — ticks indexed 2/2/4/0/0 +
  drain, `indexed_total 8/8`, `multi_tick_ingestion: true`, watermark persisted in a
  cluster state doc (`ranger-op-state`). Not a one-shot bulk import.
- **Isolated operational index** — `ranger-op-pilot-board2-test-b2`, distinct from
  the qualification index `ranger-pilot-board2-test-b2`; qualification never touched.
- **Field correctness + labeling** — sampled docs carry `@timestamp` (current era),
  `event.ingested`, identity fields, mapped security fields, `ranger.plane=operational`,
  and every event is `data.synthetic=true` (org "Valyria Financial Group", fictional).
- **Candidate isolation** — own op index readable; cross-candidate read 403;
  `.opendistro_security` and the security API denied. No protected-truth index exists
  candidate-side; truth lives only in the Ranger backend.
- **SOC admin oversight without broad security admin** — reads the operational index
  and findings; denied the security index; cannot create users.
- **Recovery (live)** — watermark persisted + read back; full-window replay produced
  8 `create` conflicts and 0 new docs (idempotent); a mapping-violating doc was
  dead-lettered while the valid doc indexed. Live 429 backpressure was not
  force-induced on a healthy cluster; it is covered offline in
  `test_telemetry_stream.py`.
- **Measured performance** — ingest ~0.16 EPS (functional profile); event→ingest
  delay p50 0 s; query latency ~10 ms; op index ~68 KB; OpenSearch heap 47% of a 1 GB
  heap; ~9.7 GB disk free. Cross-check Railway service metrics over the window.

## Bounded run + verified stop

Hard `M4_DEADLINE_S` cap; the run deletes its detector and disposable identities at
the end (`detector_deleted: true`). The `m4stop` teardown then deletes every
`ranger-op-board2test` detector across runs, drops the disposable op indices and the
op-state index, removes the disposable candidate/admin identities (also proving
revocation), and verifies `remaining_detectors: 0` / `unattended_workload_cleared:
true`. No Security Analytics workload is left running.

## Remaining limitations (honest)

- Live 429 backpressure is validated offline, not force-induced against the healthy
  cluster.
- The SA **custom** rule create returns `500 SearchPhaseExecutionException` on this
  build; not needed for the demonstrated chain (a genuine pre-packaged rule is used),
  recorded as a plugin quirk.
- Detector field mappings are keyword-typed for the op index specifically; a
  production operational plane would carry the full windows field set.

## Release posture during this milestone (unchanged)

Synthetic identity only; general candidate access and act-as disabled; enterprise
grader shadow-only; 95% bar preserved; no 25-candidate workload; no new paid
infrastructure; time-bounded run with an explicit, verified stop.
