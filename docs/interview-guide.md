# Explaining the project

## A one-minute introduction

“I built a Windows file-integrity monitoring lab using Wazuh, then connected selected alerts to Tines for Gemini-assisted triage. I monitored a controlled directory, enabled user and process attribution, and wrote custom rules for file creation, modification, and deletion. A Python integration forwards those alerts to a workflow that filters fields, requests a structured assessment, validates the result, and requires human review. I verified a real creation event through the complete path using its alert ID. The main lessons were that HTTP delivery is different from workflow completion, structured JSON is different from factual correctness, and field minimization needs to be placed at the right trust boundary.”

## Questions to be ready for

**Why use Wazuh and Tines together?**

Wazuh performs endpoint collection and deterministic detection. Tines coordinates the downstream API call and validation. Gemini helps explain evidence; it does not replace detection logic or the analyst's decision.

**What does who-data add?**

A file hash says content changed. Who-data adds available user and process context so I can investigate who made the change and how. Missing attribution should remain unknown, not be filled in by AI.

**Why custom rules instead of only the built-in FIM rules?**

The built-in rules identify event types. I use parent rule matching plus an anchored, case-insensitive path to apply a lab-specific policy to one file. I can explain and test the path scope and avoid forwarding every FIM event to an AI service.

**How did you know the full integration worked?**

I checked three things: the original Wazuh alert, the sender's forwarding result, and the final workflow JSON with the same alert identifier. A `2xx` webhook response alone only confirms that the receiving endpoint accepted the request.

**Why did a Wazuh level-10 event receive medium AI risk?**

The rule severity is predefined. The model assessed the available event context and could not establish authorization or intent. Its assessment is advisory, and I would verify the summary against the original alert.

**What is the biggest AI limitation you found?**

The output can be structurally valid and still overstate a fact. For example, the file's name and rule description call it “critical,” but that is not independent evidence of business impact. The model should attribute that label to the rule instead of asserting it as established fact.

**Does the human-review flag prevent automatic actions?**

There are no automatic actions in this workflow. The flag communicates intent; it is not an enforced approval system. An actual response workflow would need an approval gate, reviewer identity, decision record, and narrowly scoped permissions.

**What happens if an API fails?**

The demonstration lacks a durable queue and application-level retries. A failed call can leave an alert without analysis. I would add bounded retry/backoff, a dead-letter queue, and an alert-ID deduplication strategy before relying on it operationally.

**What did you build yourself, and where did AI help?**

I configured the lab, applied and tested monitoring policies, set up the integration, and inspected the observed results. AI tools assisted with workflow construction, code, and documentation. I explain the resulting behavior and limitations; I do not claim that generated code proves itself correct.

**What remains incomplete?**

Live AI results for modification/deletion, a sanitized export of the deployed workflow, repeatable authentication/error tests, and measured AI evaluation. The repository's proposed sender improvements are offline-tested references, not already deployed changes.

## Resume wording supported by the evidence

- Built a Windows FIM lab with Wazuh, including central monitoring configuration, who-data attribution, and custom rules for file creation, modification, and deletion.
- Integrated selected Wazuh alerts with a Tines/Gemini triage workflow and correlated a live creation alert through to structured analyst-review output.
- Documented validation, data-flow boundaries, AI-output limitations, and reliability improvements with reproducible reference code and synthetic tests.

Avoid claims such as “production SOC,” “autonomous incident response,” “eliminated false positives,” or percentage time savings without supporting measurements.
