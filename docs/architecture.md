# Architecture and data flow

## Lab topology

| Component | Role | Lab network |
|---|---|---|
| macOS host with VMware Fusion | Runs the VMs; browser and SSH administration | Host access to the private lab network |
| Ubuntu 24.04 LTS ARM64, `wazuh-manager` | Wazuh manager, indexer, dashboard, Filebeat; Python forwarding integration | `192.168.126.10` on the private lab interface; separate outbound interface |
| Windows 11, `win11-fim` | Wazuh agent; controlled FIM test directory | `192.168.126.130` on the private lab network |
| Tines workflow, displayed as 3B in the UI | Receives alerts, filters fields, invokes AI, validates results | Hosted service; Ubuntu initiates HTTPS delivery |
| Google Gemini API | Generates the triage candidate | Called through the Tines credential-managed connector |

Addresses are private lab values, not deployment defaults. A VMware network-settings capture and a Windows architecture inventory remain to be added. The Windows agent installation screenshot identifies version 4.14.8. A complete manager/indexer/dashboard version inventory has not been captured, so the repository does not claim exact version parity.

TCP 1515 is used for enrollment and TCP 1514 for agent communication in this lab. The Mac accesses the dashboard over HTTPS and administers Ubuntu over SSH. No inbound Internet port-forwarding is needed for the demonstrated alert flow.

## Event lifecycle

1. An operator creates, changes, or deletes the specific test file in Windows.
2. Wazuh's FIM component records the event. With who-data working, it adds the user and process responsible for the change.
3. The manager applies the custom path-specific rule and stores the alert for dashboard investigation.
4. The `custom-tines` integration receives the alert file path and webhook URL from Wazuh. It checks the rule allowlist and posts the original JSON.
5. The Tines webhook validates the request. The next stage keeps selected identifiers, rule details, agent context, file changes, hashes, audit attribution, and source MITRE data.
6. Gemini returns a structured analysis candidate. The output step checks required fields, identifier correlation, allowed values, and the mandatory review flag.
7. The analyst reads the emitted JSON in workflow history and verifies its interpretation against source evidence.

The workflow description reports request-method, JSON-shape, and body-size checks. Those exact controls still need a source export and repeatable external tests before independent code review is possible.

## Trust and data boundaries

| Boundary | What crosses it | Consequence |
|---|---|---|
| Windows → Wazuh | Endpoint FIM telemetry | Manager retains the detection evidence |
| Wazuh → Tines | Full matching alert, including fields later discarded | Tines retains the original request in execution history |
| Tines → Gemini | Selected fields, potentially including content differences | A field allowlist reduces volume; it does not guarantee the data is non-sensitive |
| Gemini → analyst | Generated assessment | Validate structure and review factual claims before acting |

The published webhook uses its generated `external_id` authentication value. That URL functions as a credential and is deliberately absent from this repository. Gemini authentication is injected by the connector using `x-goog-api-key`; the key is not part of the scripts or samples.

Only synthetic lab file content should be used with this demonstration. Before applying it to organizational telemetry, decide which fields may leave the environment, remove sensitive content before forwarding, and confirm the provider's current data-use and retention terms. Free-tier and paid-service behavior should not be assumed equivalent. [Google's billing documentation](https://ai.google.dev/gemini-api/docs/billing)

## Why these choices

- **Central configuration:** one policy controls the monitored path; a dedicated agent group would be preferable to the default group when adding more endpoints.
- **Who-data:** actor and process context make a change more explainable than a hash difference alone.
- **Path-specific rules:** a small, controlled scope makes the create/modify/delete cases easy to validate and limits irrelevant events.
- **Rule allowlists at each stage:** the manager limits invocation and the sender checks again; Tines also filters before calling the model.
- **AI after deterministic detection:** the model explains an event Wazuh already detected. It is not the primary detector.
- **Structured output:** consistent keys simplify review and future ticket integration. A valid schema cannot establish that the prose is correct.
- **No automatic response:** the demonstrated evidence is insufficient to authorize blocking accounts, stopping services, or deleting files.

## Not part of this implementation

Splunk and Airia were considered earlier, but are not in the final evidenced data path. There is no production SOC deployment, incident ticket system, threat-intelligence enrichment, enforced approval gate, or automatic remediation in this repository.
