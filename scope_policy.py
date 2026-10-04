"""Scope enforcement primitives for authorized AuthLeak scans.

The policy is deliberately deny-by-default when a scope is supplied.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable
from urllib.parse import urlparse


def _normalize(value: str) -> str:
    value = str(value or "").strip().strip(chr(96))
    if value.startswith("[") and "](" in value and value.endswith(")"):
        end = value.rfind(")")
        value = value[value.find("](") + 2 : end]
    value = value.replace(r"\.", ".").replace(r"\/", "/").replace(r"\_", "_")
    return value.strip()


@dataclass(frozen=True)
class ScopeRule:
    raw: str
    scheme: str
    host: str
    host_wildcard: bool
    port: int | None
    path: str
    path_wildcard: bool

    @property
    def concrete(self) -> bool:
        return not self.host_wildcard and not self.path_wildcard


@dataclass(frozen=True)
class ScopeDecision:
    allowed: bool
    reason: str
    matched_rule: str | None = None


class ScopePolicy:
    """Deny-by-default URL policy built from authorized structured-scope assets."""

    def __init__(self, rules: Iterable[ScopeRule]):
        self.rules = tuple(rules)

    @classmethod
    def from_identifiers(cls, identifiers: Iterable[str]) -> "ScopePolicy":
        rules = []
        for identifier in identifiers:
            rule = cls._parse_rule(identifier)
            if rule is not None:
                rules.append(rule)
        return cls(rules)

    @staticmethod
    def _parse_rule(identifier: str) -> ScopeRule | None:
        normalized = _normalize(identifier)
        if not normalized:
            return None

        if "://" not in normalized:
            normalized = f"https://{normalized}"

        parsed = urlparse(normalized)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return None
        if parsed.username or parsed.password:
            return None

        host_pattern = parsed.hostname.lower().rstrip(".")
        host_wildcard = host_pattern.startswith("*.")
        if host_wildcard:
            host_pattern = host_pattern[2:]

        path = parsed.path or "/"
        path_wildcard = "*" in path
        if path_wildcard:
            path = path.replace("*", "").rstrip("/") or "/"

        try:
            port = parsed.port
        except ValueError:
            return None

        return ScopeRule(
            raw=identifier,
            scheme=parsed.scheme.lower(),
            host=host_pattern,
            host_wildcard=host_wildcard,
            port=port,
            path=path,
            path_wildcard=path_wildcard,
        )

    @staticmethod
    def _host_matches(rule: ScopeRule, hostname: str) -> bool:
        hostname = hostname.lower().rstrip(".")
        if rule.host_wildcard:
            return hostname.endswith("." + rule.host)
        return hostname == rule.host

    @staticmethod
    def _path_matches(rule: ScopeRule, path: str) -> bool:
        path = path or "/"
        if rule.path in {"", "/"}:
            return True
        base = rule.path.rstrip("/")
        return path == base or path.startswith(base + "/")

    def decide(self, url: str) -> ScopeDecision:
        try:
            parsed = urlparse(str(url).strip())
        except ValueError:
            return ScopeDecision(False, "URL could not be parsed")

        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return ScopeDecision(False, "Only absolute HTTP(S) URLs can be tested")

        if parsed.username or parsed.password:
            return ScopeDecision(False, "URLs containing userinfo are not permitted")

        try:
            port = parsed.port
        except ValueError:
            return ScopeDecision(False, "URL contains an invalid port")

        for rule in self.rules:
            if parsed.scheme.lower() != rule.scheme:
                continue
            if not self._host_matches(rule, parsed.hostname):
                continue
            if rule.port is not None and port != rule.port:
                continue
            if not self._path_matches(rule, parsed.path):
                continue
            return ScopeDecision(True, "URL matches an authorized scope rule", rule.raw)

        return ScopeDecision(False, "URL is outside the authorized scope")

    def allows(self, url: str) -> bool:
        return self.decide(url).allowed

    def require_allowed(self, url: str) -> ScopeDecision:
        decision = self.decide(url)
        if not decision.allowed:
            raise ValueError(f"Scope blocked: {url} — {decision.reason}")
        return decision

    def concrete_targets(self) -> list[str]:
        return [rule.raw for rule in self.rules if rule.concrete]

    def describe(self) -> dict[str, object]:
        return {
            "rule_count": len(self.rules),
            "concrete_rule_count": sum(rule.concrete for rule in self.rules),
            "wildcard_rule_count": sum(not rule.concrete for rule in self.rules),
            "rules": [rule.raw for rule in self.rules],
        }
