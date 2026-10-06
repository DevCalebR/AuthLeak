"""Metadata-only authorization comparison for AuthLeak.

B3.1/B3.2 intentionally perform no network requests and never inspect
response bodies, cookies, authorization values, or other credential material.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scanner import AuthenticatedObservation


SAFE_COMPARISON_METHODS = {"GET", "HEAD", "OPTIONS"}


@dataclass(frozen=True)
class AuthorizationComparison:
    """Metadata-only comparison of victim and attacker access outcomes."""

    method: str
    url: str
    victim_status: int | None
    attacker_status: int | None
    victim_authenticated: bool
    attacker_authenticated: bool
    candidate: bool
    reason: str

    def to_dict(self) -> dict[str, object]:
        return {
            "method": self.method,
            "url": self.url,
            "victim_status": self.victim_status,
            "attacker_status": self.attacker_status,
            "victim_authenticated": self.victim_authenticated,
            "attacker_authenticated": self.attacker_authenticated,
            "candidate": self.candidate,
            "reason": self.reason,
        }


def _observation_key(
    observation: "AuthenticatedObservation",
) -> tuple[str, str]:
    """Return a stable metadata-only comparison key."""
    return observation.method.upper(), observation.url


def compare_authenticated_observations(
    victim_observations: list["AuthenticatedObservation"],
    attacker_observations: list["AuthenticatedObservation"],
) -> list[AuthorizationComparison]:
    """Compare safe authenticated observations without inspecting bodies.

    The comparison is deliberately conservative:

    - Only GET/HEAD/OPTIONS observations are considered.
    - Out-of-scope observations are ignored.
    - Both observations must represent authenticated sessions.
    - Comparisons are paired by method + URL.
    - A candidate means the access outcomes deserve manual review.
    - This function never declares a vulnerability confirmed.
    """

    victim_by_key: dict[tuple[str, str], "AuthenticatedObservation"] = {}
    attacker_by_key: dict[tuple[str, str], "AuthenticatedObservation"] = {}

    for observation in victim_observations:
        method = observation.method.upper()
        if (
            method in SAFE_COMPARISON_METHODS
            and observation.in_scope
            and observation.authenticated
        ):
            victim_by_key[_observation_key(observation)] = observation

    for observation in attacker_observations:
        method = observation.method.upper()
        if (
            method in SAFE_COMPARISON_METHODS
            and observation.in_scope
            and observation.authenticated
        ):
            attacker_by_key[_observation_key(observation)] = observation

    comparisons: list[AuthorizationComparison] = []

    for key in sorted(victim_by_key.keys() & attacker_by_key.keys()):
        victim = victim_by_key[key]
        attacker = attacker_by_key[key]

        victim_status = victim.status
        attacker_status = attacker.status

        if victim_status is None or attacker_status is None:
            candidate = False
            reason = "incomplete_access_outcome"
        elif victim_status < 400 and attacker_status < 400:
            candidate = True
            reason = "same_successful_access_outcome"
        elif victim_status < 400 <= attacker_status:
            candidate = False
            reason = "attacker_access_denied"
        elif victim_status >= 400 > attacker_status:
            candidate = True
            reason = "attacker_access_exceeds_victim"
        else:
            candidate = False
            reason = "both_access_outcomes_denied"

        comparisons.append(
            AuthorizationComparison(
                method=key[0],
                url=key[1],
                victim_status=victim_status,
                attacker_status=attacker_status,
                victim_authenticated=victim.authenticated,
                attacker_authenticated=attacker.authenticated,
                candidate=candidate,
                reason=reason,
            )
        )

    return comparisons
