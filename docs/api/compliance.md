# Compliance API Reference

Report generators and renderers for regulatory compliance assessment.
Currently supports the EU AI Act (Regulation 2024/1689).

## Package exports

```python
from agentguard.compliance import (
    ComplianceReport, EUAIActReportGenerator, Finding,
    FindingSeverity, ReportSection, SectionStatus,
    render_json, render_text,
)
```

## EUAIActReportGenerator

Generates EU AI Act compliance reports from audit logs.

::: agentguard.compliance.eu_ai_act.EUAIActReportGenerator
    options:
      show_source: true
      members_order: source

## ComplianceReport

A complete compliance report.

::: agentguard.compliance.models.ComplianceReport
    options:
      show_source: true
      members_order: source

## ReportSection

A section covering one regulatory article.

::: agentguard.compliance.models.ReportSection
    options:
      show_source: true

## Finding

A single compliance finding.

::: agentguard.compliance.models.Finding
    options:
      show_source: true

## FindingSeverity

Severity levels for compliance findings.

::: agentguard.compliance.models.FindingSeverity
    options:
      show_source: true

## SectionStatus

Status values for report sections.

::: agentguard.compliance.models.SectionStatus
    options:
      show_source: true

## Renderers

Functions for rendering reports to different formats.

::: agentguard.compliance.renderers.render_json
    options:
      show_source: true

::: agentguard.compliance.renderers.render_text
    options:
      show_source: true
