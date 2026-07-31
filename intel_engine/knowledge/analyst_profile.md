# Analyst profile — standing brief for the IntelAnalysis layer

Copy to `knowledge/analyst_profile.md` (git-ignored) and fill in. IntelAnalysis reads it at the
start of a case: your priors, thresholds, and house style. Delete the prompts, keep your answers.
Everything here is *judgment* that isn't in code — keep it generic enough to reuse across cases.

## Who I investigate
_Typical target types (investment/forex scams, diploma forgery, phishing kits, pig-butchering…),
regions/markets (e.g. VN, NG, CN operators), languages, and the tells specific to them._

## Artifacts I'll assert on
_Which artifacts you treat as attribution-grade in YOUR work, and any you'll assert same-operator on
alone (and why you trust them). Which you always down-weight (shared SEO/ad tooling, popular themes)._

## Thresholds
- **NRD cutoffs:** _your critical/high/watch day thresholds if different from the defaults._
- **Same-operator bar:** _how many attribution-grade artifacts, or which single artifact + identity._
- **Reverse-WHOIS fan-out:** _the domain count above which a registrant email = reseller/noise._
- **Wallet reuse:** _how you weight a reused wallet vs a reused owner-token._

## Registrar / hosting tells I trust
_Market-specific registrar tells (e.g. VN: Mat Bao, PA Vietnam, iNET), abuse-tolerant hosts you've
seen, NS patterns that mean privacy vs. mean bulletproof. These can seed `risk_indicators.json`._

## Money-trail priorities
_The order you chase the money (wallet → phone → email → processor → bank), the chains/tools you use
(Chainabuse, explorers), and how you handle off-platform contact handles._

## Confidence & write-up style
_Your confidence vocabulary (assessed/likely/possible) and what each requires; client-facing vs.
internal tone; how you phrase attribution for a legal/takedown audience._

## Standing don'ts
_The mistakes you've made and won't repeat — merging on a phone alone, asserting on a favicon that
turned out off-the-shelf, trusting current WHOIS over history, etc._
