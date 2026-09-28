# Validation and results

Results below distinguish screenshots of the live lab, builder-reported draft tests, and new offline reference tests. These are different kinds of evidence.

## Evidence from the lab

| Scenario | Observed evidence | Interpretation |
|---|---|---|
| Agent connection | `06-windows-agent-active.png` | The Windows agent was connected at capture time |
| Added / modified / deleted files | `09-windows-fim-events.png` | All three FIM event types are visible in Wazuh |
| Attribution and changes | `10-windows-fim-event-details.png` | Who-data, process/user context, and file-change attributes are available for a modification |
| Custom rules | `11-custom-fim-rules.png`, `12-custom-rules-validation.png`, `13-custom-fim-rule-alerts.png` | Rules are present, the displayed validation passes, and a filtered dashboard shows custom-rule activity |
| Integration start | `24-wazuh-tines-integration-active.png` | Wazuh manager is active and the integrator enables `custom-tines` |
| Live HTTP delivery | `25-wazuh-alert-forwarded-to-tines.png` | Sender records success for rule `100100`; this is not by itself AI completion |
| Live AI completion | `26-tines-live-wazuh-gemini-analysis.png`, `28-tines-human-review-required.png` | Emitted JSON preserves the source alert ID, rule ID, and human-review flag |

### Correlated live example

The source webhook-input screenshot was supplied during the build conversation but is not in the selected evidence folder. The final output is included. Add a clean input capture so a repository reader can independently compare both ends.

- Source alert ID: `1790357715.3647407`.
- Rule: `100100`, file creation.
- Source event timestamp: `2026-09-25T17:35:15.323+0000` in the submitted webhook screenshot.
- Sender log: `2026-09-25T17:35:17.765073+00:00`, successful forwarding.
- Selected final workflow output: `26/09/2026 01:35:25` in the UI.
- Model result: `medium` risk, `high` confidence, empty MITRE list, review required.

The UI and source use different time displays. Other evidence also shows a file-time/event-time discrepancy. These timestamps are useful for finding the event but are not a verified end-to-end latency benchmark. Preserve the alert identifier for correlation and verify clock synchronization before measuring performance.

## Reported draft tests

The pre-publication screenshots report that a valid Windows modification alert completed four chained step executions, rule `554` stopped at the filter, and malformed or missing JSON produced a sanitized failure. They also disclose that an earlier malformed-input test required a fix.

These are builder-reported results. The repository does not contain raw execution traces for every negative test, and isolated step tests are not identical to external delivery through the published webhook. Capture those traces before claiming independently reproduced input-validation coverage.

## Reference-code tests

See [code validation](code-validation.md) for commands and coverage. Mock HTTP responses verify local sender behavior without a live service. Reference tests are new portfolio work, not retrospective proof of the deployed sender or Tines source.

## Next live test matrix

Run each file action separately and let its event finish before the next one. Use only the disposable lab file. Capture the same alert ID in Wazuh, webhook input, and final output.

| Test | Expected result | Evidence still needed |
|---|---|---|
| Create | `100100` → analysis with source ID and review true | Already demonstrated; retain a clean correlated capture |
| Modify | `100101` → changed attributes / diff → analysis | Real endpoint-to-final-output run |
| Delete | `100102` → deletion evidence → analysis | Real endpoint-to-final-output run |
| Excluded rule | Accepted/parsed request, no model call, no final analysis | Published execution trace showing where processing stops |
| Invalid JSON / missing body | Controlled rejection; no downstream model call | Published webhook response plus sanitized logs |
| Missing/wrong external ID | Request rejected before workflow processing | Authentication-negative test with credential hidden |
| Duplicate alert | Current implementation may process twice | Demonstrate and document, then design deduplication |
| Provider timeout / quota / invalid JSON | Failed run; no successful-looking analysis | Controlled failure trace and operational recovery procedure |
| Instruction text inside a file diff | Treat as evidence, not an instruction | Adversarial synthetic sample and output review |

## How to judge AI quality

Use a small, labelled evaluation set with authorized edits, unknown changes, missing attribution, suspicious content, and benign files with alarming names. Record whether summaries match the source, whether uncertainty is stated, whether MITRE labels are supported, and whether recommended actions are appropriate. Human review of one example is not an accuracy measurement.

Do not report detection accuracy, false-positive rate, time saved, or model precision without a defined dataset and measurements.
