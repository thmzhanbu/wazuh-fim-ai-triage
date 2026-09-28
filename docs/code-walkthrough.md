# Code walkthrough and implementation decisions

The lab detects changes to one Windows test file, raises targeted Wazuh alerts,
and sends selected alerts to a cloud workflow for analyst assistance. The AI
result is evidence for a human to assess; it does not authorize a response.

## Source provenance

| File | Status | What it represents |
|---|---|---|
| [`agent.conf`](../config/agent.conf) | Reconstructed configuration | Windows group settings visible in the lab screenshot |
| [`fim_lab_rules.xml`](../config/fim_lab_rules.xml) | Reconstructed configuration | Three rules visible in the rule editor |
| [`integration.example.xml`](../config/integration.example.xml) | Sanitized configuration example | The demonstrated integration, with a nonfunctional placeholder URL |
| [`custom-tines`](../scripts/custom-tines) | Historical baseline reconstructed from the conversation | The supplied script associated with the demonstrated successful delivery; not a direct export or checksum-verified VM copy |
| [`custom-tines-hardened`](../scripts/custom-tines-hardened) | Proposed improvement, offline-tested | Safer logging, URL handling, input validation, and delivery correlation; not deployed |
| [`Test-FimLab.ps1`](../scripts/Test-FimLab.ps1) | Proposed test helper | Separate, repeatable create, modify, and delete stages |
| [`filter_alert.py`](../scripts/filter_alert.py) | Portable reference implementation | A local illustration of the documented minimization behavior; not the deployed Tines TypeScript |
| [`triage-system-prompt.md`](../config/triage-system-prompt.md), [`analysis.schema.json`](../config/analysis.schema.json) | Proposed reproduction references | Intended analysis constraints and output shape, not exports from the live workflow |
| [`samples/`](../samples/ABOUT.md) | Synthetic examples | Safe fixtures and one manually written illustrative analysis |

The actual Tines workflow export and full VM configuration exports were not
provided. This repository preserves that distinction instead of presenting
newly written reference code as deployed evidence.

## 1. Monitor changes with useful context

```xml
<directories check_all="yes" report_changes="yes" whodata="yes">C:\FIM-Lab</directories>
```

`check_all` enables the available integrity checks, including hashes and metadata.
`report_changes` records text differences. `whodata` adds the user and process
responsible for the activity. These answer different analyst questions: **what
changed, how it changed, and who or what changed it**. Windows who-data relies on
audit policy and SACL settings; other software can affect those settings. Check
the actual event's `syscheck.mode` and audit fields when troubleshooting.
[Wazuh FIM advanced settings](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/advanced-settings.html)

The test folder is deliberately narrow. Monitoring every Windows directory with
content differences would create noise and could collect sensitive content.
The demonstrated sender uploads a full matching Wazuh alert to Tines; only the
next workflow step minimizes it before the AI call. Minimization therefore does
not remove the original webhook payload from Tines history, and a retained diff
may still contain sensitive text.

## 2. Turn a generic file event into a targeted detection

| Action | Parent rule | Custom rule | Level | Source MITRE mapping |
|---|---:|---:|---:|---|
| Create | 554 | 100100 | 10 | None |
| Modify | 550 | 100101 | 12 | T1565.001 |
| Delete | 553 | 100102 | 12 | T1070.004, T1485 |

Each custom rule first requires its parent FIM event and then matches:

```xml
<field name="file" type="pcre2">(?i)^c:\\fim-lab\\critical-config\.txt$</field>
```

The anchors restrict the match to the whole path; the escaped dot is literal;
`(?i)` accepts Windows case differences. This avoids alerting on every file in
the monitored directory. `file` is the rule-engine field used by this FIM rule;
the emitted alert exposes the path as `syscheck.path`.

The levels express a lab priority choice. The filename and custom description
label the file as important for the exercise; neither proves business impact.
Similarly, an ATT&CK tag is a detection mapping. Deletion alone does not prove
defense evasion or destructive intent. An approved administrator action can
trigger the same rule. Explain this distinction in an interview.

## 3. Send only the selected rules to the workflow

```xml
<name>custom-tines</name>
<rule_id>100100,100101,100102</rule_id>
<alert_format>json</alert_format>
```

The manager filter reduces unnecessary outbound traffic. The sender repeats the
allowlist as a second check. Wazuh supports comma-separated rule filters.
[Integration configuration](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/integration.html)

The baseline script receives the alert-file path in argument 1 and the webhook
in argument 3. Argument 2 is the optional integration API key and is unused in
this design. It reads the native JSON, checks the rule ID, and makes one JSON
POST with a 15-second timeout. The standard library avoids a separate requests
dependency. Wazuh custom scripts use a `custom-` name and executable ownership
`root:wazuh`, mode `750`.
[External API integration](https://documentation.wazuh.com/current/user-manual/manager/integration-with-external-apis.html)

The baseline log says `Successfully forwarded rule …` after an HTTP 2xx reply.
That establishes receipt at the HTTP boundary. It does **not** prove that Gemini
ran, that the final validator passed, or that a human approved anything. The
final Tines output is the separate evidence for downstream completion.

The baseline deliberately remains visible as historical code, including its
limitations: it logs exception text, follows standard library redirects, has
no retry queue or deduplication, and does not log the alert ID. Exception details
can reveal sensitive request information. Do not treat it as a production
template.

The proposed hardened sender addresses a subset of those issues:

- Accepts HTTPS on the default port only and rejects redirects.
- Checks input size and basic FIM shape before sending.
- Logs fixed event names and bounded alert/rule identifiers, never the URL,
  response body, or exception text.
- Calls a 2xx result `http_acknowledged` to avoid overstating success.
- Preserves the native payload so the demonstrated Tines parser remains compatible.

It still makes one attempt. There is no new persistence, retry policy, delivery
guarantee, or idempotency implementation. The administrator remains responsible
for the configured destination. It requires a separate staging deployment and
live verification before replacing the original script.

## 4. Minimize evidence and constrain AI analysis

The portable filter keeps correlation IDs, rule context, agent details, the file
path and action, hashes, changed attributes, diff, and audit user/process. It
drops unrelated fields such as `full_log` and manager details. Run it offline:

```bash
python3 scripts/filter_alert.py < samples/alert-100101.synthetic.json
```

Filtering is field selection, not secret detection. Untrusted instructions in a
file diff remain evidence; the reference system prompt tells the AI not to obey
them. The schema restricts keys and enums and requires
`human_review_required: true`. A real output validator must also compare IDs
with the input and ensure MITRE IDs came from the source. JSON Schema alone
cannot perform those cross-document checks or prove that prose is true.

The live screenshot records a medium-risk, high-confidence assessment for rule
100100. That is one model result, not a measured detection-accuracy statistic.
No external notification or automated containment is configured in the shown
workflow.

## 5. Generate clear, repeatable evidence

Use the PowerShell helper only in the Windows lab. Each command is a separate
stage; inspect Wazuh and Tines before continuing. Preview a stage with `-WhatIf`.

```powershell
.\scripts\Test-FimLab.ps1 -Stage Create -WhatIf
.\scripts\Test-FimLab.ps1 -Stage Create
# Verify the create alert before continuing.
.\scripts\Test-FimLab.ps1 -Stage Modify
# Verify the modification and content difference before continuing.
.\scripts\Test-FimLab.ps1 -Stage Delete
```

Create refuses to overwrite an existing file. Modify appends a known marker and
prints the resulting SHA-256 hash. Delete requires its own explicit invocation
and targets only the lab file. The helper refuses a symbolic link or junction at
the monitored directory/file. It is newly supplied reference code and has not
been run on the Windows VM during repository preparation.

## Important verification commands and their purpose

Run Windows commands in Administrator PowerShell; run Linux commands on the
Ubuntu manager. These document the workflow rather than claiming another live run.

| Command | Why it matters | What it does not prove |
|---|---|---|
| `Test-NetConnection 192.168.126.10 -Port 1515` | Checks the enrollment TCP path | Agent enrollment or identity |
| `Test-NetConnection 192.168.126.10 -Port 1514` | Checks the agent event TCP path | Event decoding or alert creation |
| `Get-Service WazuhSvc` | Confirms the local agent service is running | Agent connectivity to the manager |
| `Restart-Service WazuhSvc` | Reloads the agent after relevant configuration changes | That the expected policy was applied; inspect logs |
| `sudo /var/ossec/bin/wazuh-analysisd -t` | Tests the analysis/rules configuration | A live rule match or HTTP delivery |
| `sudo python3 -m py_compile /var/ossec/integrations/custom-tines` | Checks Python syntax | Runtime permissions, networking, or valid credentials |
| `sudo chown root:wazuh /var/ossec/integrations/custom-tines` and `sudo chmod 750 /var/ossec/integrations/custom-tines` | Set the required owner/group and execution permissions | Code correctness |
| `sudo /var/ossec/bin/wazuh-integratord -t` | Tests integration configuration before a restart | A successful remote request |
| `sudo systemctl restart wazuh-manager` | Applies the changed manager configuration | Successful startup; check service and logs afterward |
| `sudo systemctl is-active wazuh-manager` | Checks manager service status | Correct behavior of every integration step |

The integration configuration test is a recommended additional preflight, not
claimed screenshot evidence. [Wazuh integratord options](https://documentation.wazuh.com/current/user-manual/reference/daemons/wazuh-integratord.html)

Before edits, preserve a private configuration backup. Merge the example XML
inside an existing `ossec_config` block and insert the generated URL privately.
Do not publish the active configuration, backups containing credentials, API
keys, or a credential-bearing webhook URL. A VM snapshot does not back up the
cloud workflow; a sanitized workflow export remains an outstanding deliverable.
