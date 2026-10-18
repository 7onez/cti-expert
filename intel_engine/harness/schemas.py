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


class TierMember(BaseModel):
    """A collected host/selector that is NOT owner-linked — kit sibling or neighbour.

    These never enter `cluster` and are NEVER attributed. They exist so the assessment can
    report what was collected without elevating a shared kit artifact or co-tenant into an
    operator claim. See `tools/kb/references/rungs.json` and SKILL.md RULE 5 rails.
    """

    node_type: str = Field(description="typed selector kind (domain, email, wallet, ip, …)")
    value: str = Field(description="the selector value")
    rung_class: str = Field(
        description="identifier class from rungs.json (e.g. ads.affiliate, favicon, "
        "wallet.exchange, ip.cotenant)"
    )
    via: str = Field(
        description="how it entered the case (shared artifact, corpus hit, counterparty, …)"
    )
    caveat: str = Field(
        description="rung caveat shown to the reader — always a not-attribution statement"
    )


class Mention(BaseModel):
    """A corpus/news/pdf hit that names a selector without binding ownership.

    Mentions are NEVER attributed and never belong in `cluster`. They surface Wayback
    collection / mediacloud / EndOfTerm / pdf hits so the reader can chase them.
    """

    selector: str = Field(description="the named selector (domain, handle, …)")
    url: str = Field(description="source URL of the mention")
    date: str = Field(default="", description="capture or publication date when known")
    snippet: str = Field(default="", description="short surrounding text when available")



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
    kit_siblings: list[TierMember] = Field(
        default_factory=list,
        description="kit-rung nodes collected but NEVER attributed — shared kit artifacts "
        "(ad/affiliate IDs, html-id, telegram.username, page-scraped contacts, bank account, "
        "unique username/string/filename/hash/title, favicon, tx id). NEVER belong in `cluster`.",
    )
    neighbours: list[TierMember] = Field(
        default_factory=list,
        description="neighbour-rung nodes collected but NEVER attributed — exchange wallets "
        "and IP co-tenants. NEVER belong in `cluster`.",
    )
    mentions: list[Mention] = Field(
        default_factory=list,
        description="news/pdf/EoT/mediacloud (and similar corpus) hits naming a selector. "
        "NEVER attributed and NEVER belong in `cluster`.",
    )



# --------------------------------------------------------------------------- cross-type Plan phase
class PlannedPivot(BaseModel):
    """One pivot the planner ADDS beyond the proposer's candidates. Validated after the phase:
    the route must exist in harness/references/pivot_map.json and accept `type`; a domain passes
    the never-seed / noise / filename guards. The planner never sizes or prices it — the count
    probe and pivot_map do — so it cannot talk an oversized or metered pivot past approval."""

    type: Literal["domain", "email", "phone", "wallet", "ip", "hash", "string", "filename",
                  "telegram"]
    selector: str = Field(description="the exact value to pivot on, as seen in the case")
    tool: str = Field(description="a pivot_map route key, e.g. urlscan.filename, wayback.telegram, "
                                  "or `collect` for a domain")
    why: str = Field(description="one sentence: what in the case makes this pivot worth its cost")


class PlanDrop(BaseModel):
    id: str = Field(description="a proposer candidate id")
    why: str = Field(description="why it should not run this round")


class Plan(BaseModel):
    """The Plan phase deliverable: re-rank the proposer's candidates and add cross-type pivots."""

    ranked: list[str] = Field(default_factory=list,
                              description="proposer candidate ids, best first; omitted ids keep "
                                          "their proposer order after these")
    added: list[PlannedPivot] = Field(default_factory=list,
                                      description="pivots the proposer did not list")
    dropped: list[PlanDrop] = Field(default_factory=list,
                                    description="candidates to skip this round, with reasons")
    notes: str = Field(default="", description="one or two sentences for the analyst")
