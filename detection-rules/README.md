# Detection rules

Rule configuration lives here as versioned YAML packs. They are the **source of
truth**: on startup (and every `MINI_SOC_RULES_RELOAD_SECONDS`, default 60 s)
the backend loads every `*.yaml` pack into the `detection_rules` table.

Rules are deliberately *not* hard-coded in Python — thresholds, windows and
tolerances are data. The rule classes in
`backend/app/detection/rules/builtin.py` only implement the detection logic.

## Pack format

```yaml
version: 1
rules:
  - rule_key: PORT_SCAN              # must match a rule class
    name: Port scan detected         # shown in the dashboard and in alerts
    category: RECONNAISSANCE
    rule_type: THRESHOLD             # THRESHOLD | PATTERN | BEHAVIORAL
    enabled: true
    severity_hint: HIGH              # LOW | MEDIUM | HIGH | CRITICAL
    mitre_id: T1046                  # optional, useful in investigations
    window_seconds: 60               # behavioural window used by the rule
    threshold: 15                    # headline threshold (for display/tuning)
    description: >-                  # why this rule exists
    recommended_action: >-           # what the analyst should do
    params:                          # rule-specific tunables
      unique_ports: 15
```

`params` are merged over the rule class defaults, so a pack only has to list the
values it wants to change.

## Shipped rules

| rule_key | Detects | Default trigger |
|---|---|---|
| `PORT_SCAN` | Reconnaissance scanning | ≥ 15 distinct destination ports from one source in 60 s |
| `BRUTE_FORCE` | Credential attacks | ≥ 5 auth failures from one source in 300 s |
| `FAILED_CONNECTIONS` | Refused/reset connection storms | ≥ 10 failures with ≥ 50 % failure ratio |
| `CONNECTION_FLOOD` | Availability attacks | ≥ 60 connections (or 120/min) from one source |
| `SUSPICIOUS_PROTOCOL` | Policy violations / tunnelling | Risky ports, large ICMP, DNS port without a question |
| `DNS_ANOMALY` | DNS tunnelling / C2 | ≥ 100 queries, or query names ≥ 60 chars, or ~all-unique queries |
| `VOLUME_ANOMALY` | Exfiltration / huge transfers | ≥ 50 MB or ≥ 500 KB/s from one host |

## Changing rules at runtime

Admins can tune rules without touching the files:

```bash
curl -X PATCH http://127.0.0.1:8000/api/v1/rules/PORT_SCAN \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"threshold": 25, "window_seconds": 120, "params": {"unique_ports": 25}}'
```

Every change bumps the rule `version`, is written to the audit log, and is
picked up by the running pipeline within one reload interval.

> Rules load *before* the API accepts traffic, so a syntax error in a pack is
> reported at startup (`log: "rule pack parse failed"`) instead of leaving the
> platform running with no detections.
