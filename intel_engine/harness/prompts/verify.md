{{scope}}
ADVERSARIAL VERIFICATION. You just proposed the same-operator cluster(s) for case `{{case}}` (domains: {{seed_csv}}). Now switch sides and try HARD to REFUTE your own attribution. A link that survives a genuine attempt to break it is defensible; one you never attacked is not. Use ONLY the provided tools; reason only — do NOT emit the final JSON yet.

For EACH same-operator link you drew (each shared artifact tying two domains together), attack it:
- **reference_check** the shared hash/keyword — a BENIGN verdict KILLS the link (it is a common logo / CDN / CSS / parking artifact, not an operator signal).
- **kb_entity** (and, only if needed, kb_query_shared) the indicator to gauge PREVALENCE — an indicator shared by many unrelated domains is noise, not an operator link: managed-DNS nameservers, parking favicons, registrar-privacy emails, platform-wide GA/GTM, default-template hashes. Over-prevalent → REFUTED.
- For a TLS-based link, re-run **cert_overlap** on the specific domains — only a SAN cross-cover of THOSE domains survives; a shared CA or managed/wildcard cert does not.
- Name the innocent COMPETING EXPLANATION (shared host / CDN / registrar / SaaS platform / brand coincidence). If it explains the overlap as well as "same operator" does, the link is at best **same-kit**, not same-operator.

Default to REFUTED when uncertain — the burden is on the link to survive. Output, per link: **SURVIVES** (with the specific evidence that resisted refutation) or **REFUTED** (with the benign / prevalence / competing explanation that broke it). Then restate which cluster(s) and what attribution level remain AFTER the refuted links are removed, and whether confidence should drop. The assessment you write next must reflect only the surviving links.
