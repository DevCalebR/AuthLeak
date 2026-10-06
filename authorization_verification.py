"""Authorization verification artifact composition for AuthLeak.

B3.7.2 composes an existing authorization comparison with deterministic
triage metadata and the B3.7.1 verification artifact contract.

This module performs no network activity and does not alter the underlying
authorization candidate decision.
"""

from __future__ import annotations

from authorization_compare import AuthorizationComparison
from authorization_triage import build_authorization_triage
from verification_artifact import (
    VerificationArtifact,
    build_verification_artifact,
)


def build_authorization_verification_artifact(
    comparison: AuthorizationComparison,
) -> VerificationArtifact:
    """Build a verification artifact from an authorization comparison."""
    triage = build_authorization_triage(comparison)
    return build_verification_artifact(comparison, triage)
