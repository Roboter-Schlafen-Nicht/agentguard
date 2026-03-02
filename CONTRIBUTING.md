# Contributing to AgentGuard

Thank you for your interest in contributing to AgentGuard! This project
aims to make autonomous AI agents safer and more auditable.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/agentguard.git`
3. Create a virtual environment: `python -m venv .venv && source .venv/bin/activate`
4. Install dev dependencies: `pip install -e ".[dev]"`
5. Run tests: `pytest`

## Development Workflow

- Create a feature branch from `main`
- Write tests first (TDD is required for all behavioral changes)
- Run the full test suite before submitting: `pytest --cov=agentguard`
- Run linting: `ruff check src/ tests/`
- Run type checking: `mypy src/`
- Submit a pull request

## Code Style

- We use [ruff](https://github.com/astral-sh/ruff) for linting and formatting
- Type hints are required for all public APIs
- Docstrings follow Google style

## Architecture

```
src/agentguard/
  policies/       -- Policy engine
  audit/          -- Audit logging
  guardrails/     -- Runtime interceptors
  compliance/     -- Report generators
  integrations/   -- Framework adapters
```

## What Makes a Good Contribution

- Bug fixes with regression tests
- New policy types with documentation
- Framework integrations (LangChain, CrewAI, AutoGen, etc.)
- Compliance report templates
- Documentation improvements

## What We Don't Accept

- Changes that add required external dependencies to the core library
- AI-generated contributions without review and testing
- Code without tests

## Reporting Issues

Please use GitHub Issues. Include:
- Python version
- AgentGuard version
- Minimal reproduction steps
- Expected vs actual behavior

## License

By contributing, you agree that your contributions will be licensed
under the same terms as the project. See [LICENSE](LICENSE) for details.
