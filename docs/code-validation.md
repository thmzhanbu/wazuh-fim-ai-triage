# Code validation record

Repository preparation date: 26 September 2026.
Final local review and repeat of the offline suite: 28 September 2026.

The reference code was checked locally without contacting a VM, webhook, Tines,
or Gemini. This supplements the screenshots; it does not extend their live-test
coverage.

## Offline tests

From the repository root:

```bash
python3 -m unittest discover -s tests -v
```

Observed result: **25 tests passed**.

| Area | Checks performed |
|---|---|
| Hardened sender | All three allowed rules, integer rule ID support, unrelated-rule suppression |
| Delivery contract | POST method, JSON content type, unchanged native body, timeout, correlation ID, HTTP-acknowledgement wording |
| Validation | Malformed JSON, invalid object shapes, missing alert file, size limit |
| Destination controls | HTTP/userinfo/fragment/invalid-port rejection; no-redirect handler installed; redirect error handling |
| Failure handling | HTTP 429, timeout, network exception, unexpected error; no implicit retry loop |
| Logs | Secret-bearing mocked exception text and URLs absent; control characters in identifiers suppressed |
| Filter reference | Correlation/hash/MITRE preservation; irrelevant-field removal; optional-field handling; excluded rule suppression |
| XML and examples | XML well-formedness; target-path positive/negative matches; schema/example key and enum consistency |

HTTP calls are mocked. Logs and inputs use temporary directories. All fixtures
contain synthetic data, including a visibly artificial `TEST_ONLY_SECRET` used
to test suppression. No real API credentials are needed.

## Additional static checks

Python files were compiled for syntax locally. Configurations and JSON fixtures
were parsed. The XML checks do not run Wazuh's configuration engine; the regular
expression test uses Python's compatible syntax for this limited expression,
not the PCRE2 engine used by Wazuh. The schema/example check tests selected
contract conditions and is **not a full JSON Schema validator**.

PowerShell was not available in the local preparation environment. The staged
Windows helper was reviewed but not parsed or executed with PowerShell. No
Windows execution claim is made for that helper.

## Evidence boundaries

| Claim | Evidence status |
|---|---|
| Original sender syntax check and manager integration enabled | Shown in lab screenshots |
| Actual Windows file creation → rule 100100 → live Tines → Gemini output | Shown in lab screenshots, including final human-review field |
| Local create/modify/delete FIM detection | Shown in Wazuh screenshots |
| Live cloud completion for rules 100101 and 100102 | Not demonstrated by the supplied live-run evidence |
| Malformed-input and excluded-rule behavior in Tines draft | Builder test report shown; independent external-request verification remains useful |
| Hardened sender behavior | 25-test suite covers sender/filter/config references; not live-deployed |
| AI factual accuracy, false-positive rate, latency distribution, resilience | Not measured |

## Next validation work

1. Capture native JSON and final output from separate live modification and deletion
   runs, preserving the same alert ID across Wazuh, webhook, and final result.
2. Export the actual Tines source and a sanitized deployment configuration. Compare
   the baseline sender with the real VM file before claiming byte-for-byte identity.
3. In a disposable staging configuration, deploy the hardened sender and verify
   valid delivery plus 401/403, 429, timeout, and 5xx outcomes without disclosing URLs.
4. Test an approved change, an unexplained change, a missing-audit-field event,
   and an instruction embedded in a file diff. Record analyst expectations and
   assess the model's claims against source evidence.
5. If moving beyond a portfolio lab, design and verify a durable retry queue,
   deduplication, error notification, retention limits, and an authenticated
   approval process. The `human_review_required` flag is metadata, not a ticket
   approval system.

These are openly documented next steps. Synthetic fixtures and local unit tests
must not be presented as extra live detections or performance measurements.
