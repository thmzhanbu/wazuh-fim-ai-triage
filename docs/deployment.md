# Deployment and troubleshooting guide

This guide explains the demonstrated setup and how to reproduce its important stages. It is not an unattended installer. Configuration files are reconstructed examples; the live Tines export still needs to be added. Review existing configuration before merging any file.

## 1. Establish the lab and connectivity

Use separate Ubuntu and Windows VMs with a private shared lab network and outbound access for installation and APIs. Install Wazuh central components using the vendor's instructions for a supported platform. Enroll the Windows agent with the manager; confirm that the dashboard lists it as active.

Run on Windows in PowerShell, replacing the IP when using a different lab network:

```powershell
Test-NetConnection 192.168.126.10 -Port 1515
Test-NetConnection 192.168.126.10 -Port 1514
Get-Service WazuhSvc
New-Item -ItemType Directory -Path 'C:\FIM-Lab' -Force
```

The connection checks distinguish an unreachable manager from a later configuration problem. The service check confirms the agent is running; it does not prove enrollment by itself. Create the monitored directory before generating test events.

## 2. Apply the monitoring policy

Merge [agent.conf](../config/agent.conf) into the appropriate group configuration on the manager. The original single-endpoint lab used `default`; a dedicated Windows lab group is clearer when managing additional agents.

The monitored path uses `check_all`, `report_changes`, and `whodata`. Verify that the agent receives the policy and that its logs report who-data monitoring for the directory. Check the required Windows auditing configuration if attribution is absent. Restarting the service alone does not prove that who-data is working. [Wazuh FIM documentation](https://documentation.wazuh.com/current/user-manual/capabilities/file-integrity/advanced-settings.html)

Do not put credentials or business-sensitive material in the test file: content differences can be collected and sent downstream.

## 3. Add and validate the detection rules

Review [fim_lab_rules.xml](../config/fim_lab_rules.xml), ensure its IDs are unused, and place it in `/var/ossec/etc/rules/`. It narrows the parent create/modify/delete rules to one anchored path.

On Ubuntu:

```bash
sudo /var/ossec/bin/wazuh-analysisd -t
```

This checks the analysis configuration for errors before restarting the manager. It does not prove that a test event will match the intended rule. Generate the event and inspect the actual alert as a separate check.

## 4. Build the workflow contract

Create these stages in Tines:

| Stage | Expected behavior |
|---|---|
| Wazuh webhook | One JSON alert per POST; validate body and use the platform's generated authenticated webhook URL |
| Filter and minimize | Continue only for `100100`, `100101`, `100102`; retain the fields needed for triage |
| Tier 1 SOC triage (AI) | Use the credential-managed Gemini connector; treat alert content as untrusted evidence |
| Emit analysis | Validate output structure and source identifiers; emit only the final analysis; require human review |

The connector shown in the evidence restricts requests to `generativelanguage.googleapis.com` and uses the `x-goog-api-key` header. Enter the key privately in the connector, not in code. Select a model actually available to the API project, record its exact identifier and settings, and test the draft before publishing.

The [reference code walkthrough](code-walkthrough.md) explains the intended filter, prompt, and output contract. These references are not an importable Tines workflow or proof of the live runtime's implementation.

## 5. Install the sender and configure the integration

The baseline [custom-tines](../scripts/custom-tines) reconstructs the demonstrated forwarding approach. For a new lab, review the separately labelled [safer reference sender](../scripts/custom-tines-hardened); adopting it is a change that requires live testing.

Back up `/var/ossec/etc/ossec.conf` and any existing sender privately before editing. From a copy of this repository on Ubuntu, installing the safer reference under Wazuh's expected integration name would be:

```bash
sudo install -o root -g wazuh -m 750 scripts/custom-tines-hardened /var/ossec/integrations/custom-tines
sudo python3 -m py_compile /var/ossec/integrations/custom-tines
```

The install command sets ownership and execute permissions. Compilation checks Python syntax; it does not check HTTP delivery or model behavior. The safer sender logs its component as `custom-tines-hardened` even when installed under `custom-tines`.

Insert [integration.example.xml](../config/integration.example.xml) **inside an existing `ossec_config` block** in the manager configuration. Replace its entire placeholder URL privately with the existing generated live webhook URL. Escape ampersands as `&amp;` in XML. The integration name must match the installed filename.

Validate and reload:

```bash
sudo /var/ossec/bin/wazuh-analysisd -t
sudo /var/ossec/bin/wazuh-integratord -t
sudo systemctl restart wazuh-manager
sudo systemctl is-active wazuh-manager
sudo grep -i integrator /var/ossec/logs/ossec.log | tail -n 10
```

Run the restart only after both validation commands succeed. The final log check establishes that the integrator started and recognized the custom integration. It does not establish a completed AI analysis. [Integration setup](https://documentation.wazuh.com/current/user-manual/manager/integration-with-external-apis.html), [integrator configuration test](https://documentation.wazuh.com/current/user-manual/reference/daemons/wazuh-integratord.html)

## 6. Test one event at a time

Use the staged PowerShell lab script in [scripts](../scripts/) for the disposable `C:\FIM-Lab\critical-config.txt` file. Start with creation, confirm the result, then modification, then deletion. Do not run the deletion stage against a file you need to retain.

For each event:

1. Find the Wazuh alert and record its ID, rule ID, action, path, user, process, and timestamp.
2. Check the sender log: `sudo tail -n 10 /var/ossec/logs/integrations.log`.
3. Locate the corresponding webhook execution, then its final `Emit analysis` output.
4. Compare identifiers and evidence fields. Review whether the prose contains unsupported assumptions.
5. Save the final result with credentials hidden and record the observed outcome in the test matrix.

## Troubleshooting by boundary

| Symptom | First checks |
|---|---|
| Agent disconnected | Service, manager address, private-network connectivity, enrollment |
| No FIM event | Group assignment, policy received, monitored path exists, baseline complete, agent logs |
| Event exists but custom rule missing | Parent rule, exact path/escaping, rule ID collision, manager validation |
| No forwarding | Integration loaded, rule allowlist, filename and permissions, integration logs |
| HTTP failure | Outbound DNS/HTTPS, generated URL, authentication, server status; keep secrets out of logs |
| HTTP success but no analysis | Workflow execution state, filter result, Gemini quota/provider error, output validation |
| Analysis looks plausible but inaccurate | Compare every factual claim with the source alert; inspect prompt and missing context |

## Rollback

Remove the newly added integration block or restore the saved manager configuration, validate it, and restart the manager. Restore prior rules/group settings if those were changed. Disable the published workflow if its receiving endpoint should stop accepting lab events. Preserve evidence and logs needed for troubleshooting, but do not commit raw credentials or private exports.
