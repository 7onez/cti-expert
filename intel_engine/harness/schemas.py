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


class Alternative(BaseModel):
    """One benign / competing explanation, put to the evidence.

    Kept as its own list rather than folded into `gaps` because a reader auditing an attribution
    needs to see WHICH innocent readings were tested and what decided each one. A table where every
    row is `rejected` is advocacy, not analysis — `cannot_rule_out` is a first-class outcome and
    must be reflected in `confidence`.
    """

    explanation: str = Field(
        description="the competing explanation in one line (shared hosting panel, prior owner of "
        "the domain, common-name collision, CDN/provider co-tenancy, …)"
    )
    status: Literal["rejected", "cannot_rule_out", "partially_rejected"] = Field(
        description="what the evidence did to it"
    )
    why: str = Field(
        description="the SPECIFIC observation that decided it — an artifact, a date, a prevalence "
        "count. Never 'unlikely'."
    )


class Assessment(BaseModel):
    """The IntelAnalysis deliverable — mirrors the §7 write-up standard."""

    decision_supported: str = Field(
        default="",
        description="one sentence: the question this assessment answers AND the decision it is "
        "meant to support (registrar/host referral, platform enforcement, law-enforcement matter, "
        "publication, or internal analytic reference). Sets the threshold of proof the reader "
        "should apply; without it the reader silently applies their own.",
    )
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
    alternatives: list[Alternative] = Field(
        default_factory=list,
        description="the competing explanations considered, each with its status and the evidence "
        "that decided it. At least one entry whenever an attribution level above 'inconclusive' is "
        "claimed — an unrejected alternative caps the confidence of the judgment it threatens.",
    )
    gaps: list[str] = Field(
        default_factory=list,
        description="what could not be verified — including what a keyless / passive / blocked "
        "collection could not have seen. Alternatives go in `alternatives`, not here.",
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
