"""Structured checkpoint schemas for the OSINT harness.

Only the FINAL assessment is schema-forced (via ClaudeAgentOptions.output_format).
Keep it focused — deeply nested schemas with many required fields are harder for
the model to satisfy and raise the odds of error_max_structured_output_retries.
"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class ClusterMember(BaseModel):
    domain: str
    shared_artifacts: list[str] = Field(
        default_factory=list,
        description="the concrete indicators that bind this domain to the cluster "
        "(GA4/GTM ID, favicon hash, registrant email, reused wallet, …)",
    )


class Assessment(BaseModel):
    """The IntelAnalysis deliverable — mirrors the §7 write-up standard."""

    bluf: str = Field(
        description="bottom line up front: one sentence with an estimative word "
        "(assessed / likely / possible)"
    )
    cluster: list[ClusterMember] = Field(default_factory=list)
    attribution_level: Literal[
        "same-kit", "same-operator", "same-actor", "inconclusive"
    ] = Field(description="the strongest claim the evidence supports")
    confidence: Literal["low", "moderate", "high"]
    evidence: list[str] = Field(
        default_factory=list,
        description="cited artifacts justifying the attribution level",
    )
    gaps: list[str] = Field(
        default_factory=list,
        description="what could not be verified, and the competing explanation ruled out",
    )
    next_pivots: list[str] = Field(
        default_factory=list, description="prioritised open leads, highest yield/cost first"
    )
    # --- the intake premise, answered. See harness/case_scope.py and WebPivot §0 Intake.
    # A case arrives with a claim attached ("this scam site", "their C2"); without these two
    # fields the claim never gets answered and silently becomes the frame the whole assessment
    # was written inside. Both default to the honest value for "nobody tested it", so an older
    # caller or a model that omits them cannot accidentally assert that a premise was confirmed.
    premise: str = Field(
        default="",
        description="the claim this run was given, verbatim if supplied — otherwise the target "
        "class the run ASSUMED, marked as assumed",
    )
    premise_verdict: Literal[
        "supported", "partially_supported", "not_supported", "contradicted", "inconclusive"
    ] = Field(
        default="inconclusive",
        description="what the COLLECTION says about that claim. not_supported = found nothing "
        "either way (on a keyless/passive/blocked run that is a fact about the collection, not "
        "the target); inconclusive = the target was never observed, so the claim was not tested. "
        "Neither means benign.",
    )
