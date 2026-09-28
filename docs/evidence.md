# Evidence index

The selected screenshots were copied unchanged from the lab evidence folder. Original filenames are retained, including gaps and repeated number prefixes. [SHA-256 checksums](../evidence/SHA256SUMS.txt) identify these copies; they do not establish when or how the original screenshots were created.

## Detection and collection

| Screenshot | What to look for | Limit of the evidence |
|---|---|---|
| [06 — active agent](../evidence/06-windows-agent-active.png) | `win11-fim`, active status, agent version | A point-in-time connection |
| [07 — central policy](../evidence/07-windows-fim-central-configuration.png) | Windows scope, `C:\FIM-Lab`, change reporting, who-data | Editor content alone does not prove application |
| [08 — loaded configuration](../evidence/08-windows-fim-configuration-loaded.png) | Agent log records the monitored directory and options | Supports application of the policy shown in 07 |
| [09 — native FIM events](../evidence/09-windows-fim-events.png) | Added, modified, deleted; rules `554`, `550`, `553` | These are the built-in rules, not the custom IDs |
| [10 — investigation detail](../evidence/10-windows-fim-event-details.png) | User/process, who-data mode, content diff, hashes and changed attributes | File timestamps need reconciliation; no latency claim |
| [11 — custom rule definitions](../evidence/11-custom-fim-rules.png) | Parent rule matching and exact lab path | Definition and MITRE metadata, not proof of malicious activity |
| [12 — rule validation](../evidence/12-custom-rules-validation.png) | Successful validation and active manager | Configuration validity is distinct from event matching |
| [13 — custom-rule activity](../evidence/13-custom-fim-rule-alerts.png) | Filter includes `100100`, `100101`, `100102` | Add an event table for explicit per-rule/action mapping |

## Integration and analysis

| Screenshot | What to look for | Limit of the evidence |
|---|---|---|
| [18 — Gemini connector](../evidence/18-gemini-api-connector-active.png) | Allowed API host, custom header, masked key, Active status | Does not establish model version, quota, or indefinite free use |
| [20 — draft validation summary](../evidence/20-tines-prepublication-tests-pass.png) | Reported malformed/missing JSON, valid sample, excluded rule checks | Builder-authored summary; raw test traces remain missing |
| [24 — integrator active](../evidence/24-wazuh-tines-integration-active.png) | Final lines enable `custom-tines` | Earlier “not configured” log lines predate the working configuration |
| [25 — forwarding checkpoint](../evidence/25-wazuh-alert-forwarded-to-tines.png) | Successful forwarding of rule `100100` | HTTP acknowledgment, not downstream completion |
| [26 — live final analysis](../evidence/26-tines-live-wazuh-gemini-analysis.png) | Alert ID, rule `100100`, file action, evidence and model assessment | One live created-file result |
| [28 — required review](../evidence/28-tines-human-review-required.png) | Same output, recommendations and `human_review_required: true` | Advisory field, not a technical approval gate |

Some workflow screenshots retain earlier builder messages such as “Not pushed live.” The later version indicator and execution output establish the state relevant to the demonstrated run. New output-focused captures would be easier to read.

## Provenance of the code

The screenshots are lab evidence. The text files in `config/` and baseline sender reconstruct visible configuration and the demonstrated approach; they are not a byte-for-byte export of the deployed environment. The safer sender, reference transformations, samples, and local tests were prepared for this repository and are labelled accordingly. The live Tines workflow has not been exported into this repository.

## Most useful additional captures

1. A custom-rule Events table showing all three IDs alongside action, agent, path, and level.
2. A live modification result and a live deletion result, each correlated to its Wazuh alert ID.
3. A clean paired capture of the creation alert's source/webhook input and final output.
4. Actual negative-test execution records, including rejection before an AI call.
5. A component-version inventory and synchronized clock/timezone checks.
6. An analyst disposition note explaining whether the lab action was expected and which evidence supports that conclusion.

Capture the result pane at a readable size. Keep authentication values hidden and retain the original context needed to understand the event. Source files and sanitized JSON are usually more useful than additional screenshots of code or documentation.
