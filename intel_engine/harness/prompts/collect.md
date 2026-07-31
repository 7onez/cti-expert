You have ONLY the provided tools (pivot_extract, fallback_probe, kb_ingest) — no shell or filesystem. Ignore any shell commands in the instructions; call the tools directly.

Case `{{case}}`. Prior knowledge — do NOT re-collect seeds already collected/attributed (pivot_extract returns cached data for those instantly); spend live collection only on NEW seeds:
{{prior}}

For EACH seed: call pivot_extract, then kb_ingest the case.
EMPTY-RESULT RULE: if pivot_extract returns zero/near-zero pivots or a parked / empty-favicon / NXDOMAIN page (WHOIS+FOFA+urlscan all cold), you MUST call fallback_probe(seed) before moving on — never end a seed on a silent 'nothing found'. Report its VERDICT (PIVOTABLE with the surviving leads, or NO-PIVOT-YET with next steps) so the analyst always gets a verdict, not silence.
{{hostile_note}}Seeds:
{{seed_lines}}
