# Compliance Reports

AgentGuard can generate compliance reports from audit log data. Currently
supports the EU AI Act framework.

## EU AI Act reports

The `EUAIActReportGenerator` evaluates audit logs against four articles
of the EU AI Act:

| Article | Topic |
|---------|-------|
| Art. 9 | Risk Management |
| Art. 12 | Record-Keeping |
| Art. 13 | Transparency |
| Art. 14 | Human Oversight |

### Generating a report

```python
from agentguard import AuditLog
from agentguard.compliance import EUAIActReportGenerator, render_text, render_json

# Load audit data
log = AuditLog.load("audit.jsonl", "session-001")

# Generate report
generator = EUAIActReportGenerator()
report = generator.generate(log)

# Render as text
print(render_text(report))

# Render as JSON
print(render_json(report))
```

### Writing to a file

```python
render_text(report, output="report.txt")
render_json(report, output="report.json")
```

## Report structure

A `ComplianceReport` contains:

| Field | Type | Description |
|-------|------|-------------|
| `framework` | str | Framework name (e.g. "EU AI Act") |
| `generated_at` | datetime | When the report was created |
| `sections` | list | One section per article/requirement |
| `summary` | str | Overall compliance summary |

Each `ReportSection` contains:

| Field | Type | Description |
|-------|------|-------------|
| `title` | str | Section title (e.g. "Art. 9 - Risk Management") |
| `status` | SectionStatus | `compliant`, `partial`, or `non_compliant` |
| `findings` | list | Specific findings |
| `recommendations` | list | Improvement suggestions |

## CLI usage

```bash
# Text report to stdout
agentguard report eu-ai-act audit.jsonl --session session-001

# JSON report
agentguard report eu-ai-act audit.jsonl --session session-001 --format json

# Write to file
agentguard report eu-ai-act audit.jsonl --session session-001 --output report.txt
```

## Custom frameworks

The compliance module is designed to be extensible. To add a new
framework, create a report generator that accepts an `AuditLog` and
returns a `ComplianceReport`:

```python
from agentguard.compliance.models import ComplianceReport, ReportSection

class MyFrameworkReportGenerator:
    def generate(self, audit_log: AuditLog) -> ComplianceReport:
        # Analyze audit_log.entries and build sections
        ...
```
