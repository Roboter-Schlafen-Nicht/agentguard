# Changelog

All notable changes to AgentGuard will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-03-03

### Added

- **Policy Engine**: YAML and Python-defined policies with Guard evaluation
- **Built-in Policies**: no-force-push, no-secret-exposure, no-data-deletion
- **Audit Logging**: Hash-chained, append-only JSONL audit logs with integrity verification
- **Audit Query API**: Filter audit entries by time range, action type, and actor
- **Guardrails**: Action interceptor with pre/post hooks and policy enforcement
- **Compliance Reporting**: EU AI Act report generator (Articles 9, 12, 13, 14)
- **JSON and Plaintext Report Renderers**
- **MCP Server**: Transparent proxy with policy enforcement for shell, file read, and file write tools
- **MCP Tools**: `agentguard_status` and `agentguard_audit_query` introspection tools
- **CLI Tool**: `agentguard check`, `agentguard audit`, `agentguard report`, `agentguard policies`, `agentguard version`
- **Documentation Site**: MkDocs Material site with API reference
- **CI/CD**: GitHub Actions for testing (Python 3.10-3.13), linting, type checking
- **Release Workflow**: Tag-triggered release with version validation and PyPI publish via trusted publisher

[Unreleased]: https://github.com/Roboter-Schlafen-Nicht/agentguard/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Roboter-Schlafen-Nicht/agentguard/releases/tag/v0.1.0
