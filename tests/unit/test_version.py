"""Smoke test: package imports and version is set."""

from agentguard import __version__


def test_version_is_set() -> None:
    assert __version__ == "0.2.0"


def test_version_is_string() -> None:
    assert isinstance(__version__, str)
