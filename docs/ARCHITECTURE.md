# Architecture

GateShield has one core responsibility: translate repository intent and detected stack into reproducible security checks and a stable gate/report contract.

```text
.gateshield.yml + repository
             |
             v
          autodetect
             |
             v
        execution plan
             |
             v
     scanner adapters
             |
             v
      normalized model
             |
     +-------+--------+
     |                |
 baseline          artifacts
     |                |
     +-------+--------+
             v
        policy gate
             |
             v
 JSON / Markdown / SARIF
```

The CLI is CI-agnostic. GitHub-specific artifact upload and SARIF publication live in `action.yml` and the reusable workflow.
