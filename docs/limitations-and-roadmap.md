# Engineering decisions and next steps

The lab demonstrates detection, forwarding, and AI-assisted triage. The next work is to make it reproducible and operationally reliable.

## Highest priority

| Gap | Why it matters | Concrete next action |
|---|---|---|
| No sanitized export of deployed source | Screenshots cannot reproduce every implementation detail | Export the four Tines steps, prompt, model settings, output validation, and active Wazuh files; remove secrets; compare with reference code |
| Only creation has live AI evidence | Modification/deletion tests inside Wazuh do not prove the whole workflow | Capture real `100101` and `100102` runs with matching source and final alert IDs |
| No measured AI quality | Valid JSON can still contain unsupported claims | Add labelled synthetic cases and record human-reviewed results |
| Review flag is advisory | A boolean does not create ownership or enforce approval | Add a case queue with assigned reviewer, decision, timestamp, and audit trail if the lab is extended |
| No durable delivery mechanism | Network or provider failure can lose an analysis; replay can duplicate it | Add persistent queue, bounded retries/backoff, dead-letter handling, and deduplication by source alert ID |

## Further improvements

- **Safer logs and transport:** the reconstructed baseline logs exception text, which can contain sensitive values. A separate proposed sender uses sanitized events, HTTPS validation, payload limits, and redirect rejection. It has not been deployed to the lab.
- **Data minimization before cloud transfer:** the current workflow minimizes only after Tines receives the original alert. Move appropriate filtering/redaction to the manager if raw content must stay local; validate that enough evidence remains for analysis.
- **Prompt injection resistance:** a file diff may contain attacker-controlled instructions. Treat all alert strings as untrusted evidence and test that they cannot alter output requirements or trigger tools.
- **Access and secret management:** restrict who can edit workflows and connectors; keep generated webhook URLs and API keys outside Git. Masked screenshots are evidence of UI configuration, not proof of credential lifecycle controls.
- **Operational monitoring:** record separate counters for received, filtered, HTTP-acknowledged, AI-completed, validation-failed, and reviewed events. Alert on failures without logging sensitive bodies.
- **Clock consistency:** verify time synchronization on both VMs and record the dashboard timezone before timing experiments.
- **Configuration scope:** use a dedicated Windows lab agent group when expanding beyond this single endpoint.
- **Version inventory and recovery:** record component versions and take a lab snapshot/backup before changes. Existing screenshots do not establish that backups were taken.
- **Cost and rate limits:** record the selected model and project quota. A successful lab run does not imply unlimited free processing.

## Detection interpretation

The custom rules intentionally assign stronger severities to one named lab file. That choice expresses a local policy; it does not prove business criticality. Rule level and the model's risk classification answer different questions and need not match.

MITRE tags describe potentially relevant behaviors. A generic modification is not proof of malicious data manipulation, and deleting a test file is not proof of defense evasion or destructive impact. Preserve those tags as rule metadata and explain uncertainty.

## What I would add for a production pilot

Begin with a narrowly scoped, approved set of telemetry and a defined data-handling policy. Add reliable delivery, event deduplication, operational ownership, model-output evaluation, and an enforced analyst decision process. Only then consider integrations that can change endpoint state. None of those production controls is claimed as completed here.
