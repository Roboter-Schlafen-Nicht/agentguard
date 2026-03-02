# Installation

## Requirements

- Python 3.10 or later
- pip (or any PEP 517-compatible installer)

## Install from PyPI

```bash
pip install agentguard
```

## Install with MCP support

To use the MCP server for Claude Desktop integration:

```bash
pip install agentguard[mcp]
```

## Install from source

```bash
git clone https://github.com/Roboter-Schlafen-Nicht/agentguard.git
cd agentguard
pip install -e ".[dev]"
```

## Verify installation

```bash
agentguard version
```

Or from Python:

```python
import agentguard
print(agentguard.__version__)
```

## Optional dependencies

| Extra | Description |
|-------|-------------|
| `mcp` | MCP server support (`mcp>=1.0`) |
| `dev` | Development tools (pytest, ruff, mypy) |
| `docs` | Documentation build (mkdocs-material, mkdocstrings) |
