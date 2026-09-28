# Sample data provenance

All `*.synthetic.json` inputs are newly created fixtures based on the field names
visible in the lab evidence. They are not exported alerts or additional live
tests. The reserved documentation address `192.0.2.130`, demo hostname, user, IDs,
and timestamps are synthetic. File hashes are calculated from fixed fixture
content, not copied from the live system.

`analysis-100101.illustrative.json` is a manually authored example of the proposed
output contract. It is not Gemini output and is not evidence that rule `100101`
completed the live cloud workflow. The live screenshot proves rule `100100`.

Offline example, from the repository root:

```bash
python3 scripts/filter_alert.py < samples/alert-100101.synthetic.json
```

The filter emits selected native fields under a smaller structure. It is a
reference reimplementation, not the original Tines source. It retains the diff
when present; minimization is not secret redaction.
