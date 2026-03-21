"""Domain allowlist policy type.

Provides a policy that allows actions only when the target domain
is in an allowlist. Supports exact domains, wildcard subdomains
(``*.example.com``), and built-in presets for popular services.

Usage::

    from agentguard.policies.domain_allowlist import DomainAllowlist
    from agentguard.policies.guard import Guard

    policy = DomainAllowlist(
        name="web-access",
        domains=["api.github.com"],
        presets=["google"],
        action_kind="web_request",
    )
    guard = Guard(policies=[policy])
    decision = guard.check("web_request", url="https://api.github.com/repos")

YAML format::

    name: web-access
    type: domain_allowlist
    action: web_request
    domains:
      - api.github.com
      - "*.internal.corp"
    presets:
      - github
      - google
"""

from __future__ import annotations

import logging
from urllib.parse import urlparse

from agentguard.policies.models import Action, Context, Decision, Policy, Severity

logger = logging.getLogger(__name__)

#: Built-in domain presets for popular services.
PRESETS: dict[str, list[str]] = {
    "github": [
        "github.com",
        "*.github.com",
        "api.github.com",
        "raw.githubusercontent.com",
        "*.githubusercontent.com",
    ],
    "google": [
        "google.com",
        "*.google.com",
        "googleapis.com",
        "*.googleapis.com",
    ],
    "openai": [
        "api.openai.com",
        "openai.com",
    ],
    "anthropic": [
        "api.anthropic.com",
        "anthropic.com",
    ],
    "pypi": [
        "pypi.org",
        "files.pythonhosted.org",
        "*.pythonhosted.org",
    ],
    "npm": [
        "registry.npmjs.org",
        "npmjs.com",
        "*.npmjs.com",
    ],
    "docker": [
        "docker.io",
        "*.docker.io",
        "registry-1.docker.io",
        "hub.docker.com",
    ],
}


class DomainAllowlist(Policy):
    """Policy that allows actions only for whitelisted domains.

    Checks ``url`` and ``domain`` parameters in actions against an
    allowlist of domains. Supports exact match and wildcard
    subdomains (``*.example.com``).

    Args:
        name: Policy name.
        domains: List of allowed domain patterns.
        presets: List of preset names to include.
        action_kind: The action kind this policy applies to
            (default: ``web_request``).
        description: Optional description.

    Raises:
        ValueError: If neither domains nor presets are provided,
            or if an unknown preset is referenced.
    """

    def __init__(
        self,
        name: str,
        domains: list[str] | None = None,
        presets: list[str] | None = None,
        action_kind: str = "web_request",
        description: str | None = None,
    ) -> None:
        if not domains and not presets:
            msg = "At least one of domains or presets must be provided"
            raise ValueError(msg)

        # Validate presets
        if presets:
            for preset in presets:
                if preset not in PRESETS:
                    msg = f"Unknown preset: {preset!r}"
                    raise ValueError(msg)

        # Build the full domain set
        all_domains: list[str] = []
        if domains:
            all_domains.extend(domains)
        if presets:
            for preset in presets:
                all_domains.extend(PRESETS[preset])

        # Normalize: lowercase, deduplicate
        self._exact_domains: set[str] = set()
        self._wildcard_suffixes: set[str] = set()
        for d in all_domains:
            d_lower = d.lower()
            if d_lower.startswith("*."):
                # *.example.com -> match any .example.com suffix
                self._wildcard_suffixes.add(d_lower[1:])
            else:
                self._exact_domains.add(d_lower)

        self._action_kind = action_kind

        # Initialize the parent Policy with no rules
        # (we override evaluate() entirely)
        super().__init__(
            name=name,
            rules=[],
            description=description,
        )

    def evaluate(
        self,
        action: Action,
        context: Context | None = None,
    ) -> Decision:
        """Evaluate an action against the domain allowlist.

        Checks ``url`` and ``domain`` params. If the action kind
        doesn't match, the action is allowed (pass-through).

        Args:
            action: The action to check.
            context: Unused (present for API compatibility).

        Returns:
            Allow if domain is in allowlist, deny otherwise.
        """
        if action.kind != self._action_kind:
            return Decision(allowed=True)

        # Try to extract domain from params
        domain = self._extract_domain(action)
        if domain is None:
            # No domain info found — deny by default
            return Decision(
                allowed=False,
                denied_by=self.name,
                reason=(f"No domain found in action params (policy: {self.name})"),
                severity=Severity.HIGH,
            )

        return self.evaluate_domain(domain)

    def evaluate_domain(self, domain: str) -> Decision:
        """Check a domain string against the allowlist.

        Args:
            domain: The domain to check.

        Returns:
            Allow if domain is in allowlist, deny otherwise.
        """
        domain_lower = domain.lower()

        # Exact match
        if domain_lower in self._exact_domains:
            return Decision(allowed=True)

        # Wildcard match: check if domain ends with any wildcard suffix
        for suffix in self._wildcard_suffixes:
            if domain_lower.endswith(suffix):
                return Decision(allowed=True)

        return Decision(
            allowed=False,
            denied_by=self.name,
            reason=(f"Domain {domain!r} not in allowlist (policy: {self.name})"),
            severity=Severity.HIGH,
        )

    def evaluate_url(self, url: str) -> Decision:
        """Check a URL against the domain allowlist.

        Parses the URL to extract the hostname and checks it.

        Args:
            url: The URL to check.

        Returns:
            Allow if the URL's domain is in allowlist, deny otherwise.
        """
        domain = self._parse_domain_from_url(url)
        if domain is None:
            return Decision(
                allowed=False,
                denied_by=self.name,
                reason=(
                    f"Could not parse domain from URL {url!r} (policy: {self.name})"
                ),
                severity=Severity.HIGH,
            )
        return self.evaluate_domain(domain)

    def _extract_domain(self, action: Action) -> str | None:
        """Extract domain from action params.

        Checks ``domain`` param first, then tries to parse ``url``.
        """
        # Direct domain param
        domain = action.params.get("domain")
        if isinstance(domain, str) and domain:
            return domain

        # URL param
        url = action.params.get("url")
        if isinstance(url, str) and url:
            return self._parse_domain_from_url(url)

        return None

    @staticmethod
    def _parse_domain_from_url(url: str) -> str | None:
        """Parse hostname from a URL string."""
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname
            if hostname:
                return hostname
        except Exception:
            pass
        return None
