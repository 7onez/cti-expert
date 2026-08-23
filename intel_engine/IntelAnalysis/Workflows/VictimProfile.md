# Workflow: Profile the victims → infer the access vector

Encodes IntelAnalysis SKILL.md §1.6. Run it whenever the operator is serving from **hostnames they
do not own** — a phishing page on a subdomain of a legitimate business, a compromised CMS, a
dangling record. It answers a question the operator-side analysis cannot: *what capability did they
need to obtain these names, and did they build it or buy it?*

Run from the project root. Placeholders: `<case>` = the case folder under `cases/`.

## When to run it

Trigger on any of these:

- the seed's **apex resolves somewhere else** than the malicious label, and the apex looks like a
  real business;
- WHOIS shows an ordinary registrant whose registrar, nameservers and creation date are **unchanged**;
- a wildcard exists on the zone and the malicious label **overrides** it (that is a deliberately
  added record, not a leftover);
- the same operator's hosts sit on **several unrelated parent domains**.

## Steps

1. **Enumerate victims before profiling them.** The analysis is only as good as the victim set, and
   a set of two or three will look "concentrated" on every dimension by chance. Sweep each known
   victim apex for *other* hijacked labels and re-resolve every result — certificate transparency
   plus passive DNS/reverse-IP on the operator's addresses is the productive pair. Every new victim
   at a **new provider** is worth more than ten more hosts at one you already have, because
   provider diversity is what discriminates the hypotheses.

2. **Separate victims from the operator's own domains.** A name the operator *registered* has no
   victim. Counting it inflates provider diversity and corrupts every concentration — pass it to
   `--exclude`. The tool cannot detect this; only you know which names they bought.

3. **Profile the set.**
   ```bash
   python3 tools/kb/victim_profile.py --case <case> \
       --exclude <operator-registered-apex,...> \
       -o cases/<case>/victim_profile.json
   ```
   Or profile an explicit list: `python3 tools/kb/victim_profile.py a.example b.example …`

   Everything is **passive** — public DNS and records you already hold. The victims are not the
   target and are never scanned or probed; the control panel is identified from the subdomains a
   panel creates in its own customer's zone (`cpanel.`, `webdisk.`, `cpcalendars.`, …).

4. **Read the shape against the base rates.** The tool prints per-dimension concentration and the
   hypotheses whose thresholds are met. Before believing any concentration, ask what a random draw
   of small-business domains would have produced — cPanel and WordPress dominate by default, and
   the tool flags those as base-rate confounded rather than silently counting them. A concentration
   on a **minority** platform or a **small regional** provider is the informative one.

5. **Read the demography (country x sector).** The tool prints both distributions and a reading.
   Country comes from the WHOIS **registrant country**, else the ccTLD — never from hosting, which
   measures where the victim's *provider* is and would turn any Cloudflare-fronted set into a US
   cluster. Sector is derived from the domain name and registrant organisation only (we do not
   fetch the victim's homepage), so it is frequently under-covered and is reported as
   *"coverage too low to read"* rather than guessed.

   **Check the regional sub-clusters even when the overall verdict is dispersion** — a country +
   small-provider grouping hiding inside a dispersed set is usually the most actionable finding in
   the case, because that one provider can find the victims you have not. Country also names the
   **national CERT/CSIRT** to notify.

6. **Date the onsets.** Take the first certificate-transparency issuance for each hijacked label as
   the tightest available bound on when the operator got in. Compressed onset = one bulk credential
   dump being worked through; a spread over months = ongoing access or a drip-fed broker
   relationship. Same victims, different urgency.

7. **Write the vector judgment, and let it drive the recommendation.** This is the point of the
   whole workflow — the remediation differs by vector:

   | Vector | Who fixes it | What a page takedown achieves |
   |---|---|---|
   | Provider breach | that provider's IR team | little — they can re-add |
   | Panel exploit | the panel vendor, via patch | little until patched |
   | CMS/plugin exploit | the plugin vendor + victim updates | little until patched |
   | Reseller / agency | the agency's credential reset | little until reset |
   | **Credential supply** | **per-victim panel resets + MFA** | **almost nothing — they move to the next name** |

   State the vector, the victim shape that supports it, and the alternative you ruled out.

8. **Report to the providers, not only the brand.** Victim-side findings are actionable by people
   who are not your client: give each hosting provider the list of *their* customer zones carrying
   attacker records, and ask them to sweep for the operator's addresses across their whole estate.
   That is usually the highest-leverage output of the entire case.

## Output

`cases/<case>/victim_profile.json` — per-victim profiles plus the assessment block
(`shape`, `supported`, `verdict`). Feed the verdict into the assessment's access-vector section and
the provider list into the recommendations.

## Failure modes

- **Too few victims** → the tool refuses to call it (`INSUFFICIENT VICTIMS`). That is correct; go
  back to step 1 rather than lowering the threshold.
- **Believing a base-rate concentration.** cPanel at 100% across five providers is what you would
  expect anyway. Demand a shared version before you promote it.
- **Counting operator-registered domains as victims** (step 2) — the most common way this analysis
  goes wrong.
- **Treating dispersion as "no result".** Dispersion *is* the result: it names a credential supply.
- **Reading the country off the hosting.** Hosting identifies the victim's provider, not the victim.
  Use the registrant country.
- **Missing a regional sub-cluster** because the top-level verdict said "dispersed".
