# Admin / Sensitive-Endpoint Indicators

A reusable vocabulary + rules for flagging **admin panels and sensitive
endpoints** from any URL, subdomain, or path the skill encounters — during
`/subdomain`, `/sweep`, `/query`, web/DNS recon, `/stealer-log`, and reporting.
The reference implementation is `classify_endpoint()` in
`scripts/stealer_log_parse.py`; apply the same rules manually when no script runs.

> An admin/agent/back-office endpoint on a target = a high-value finding (attack
> surface for your own org; actor infrastructure when profiling a threat actor).
> Tag each as an IOC and pivot (`/threat-check`, `/whois`, `/subdomain`, `/branch`).

---

## Match rules

Detect on the **leftmost subdomain label** *or* any **path segment**. Strong
indicators match by **prefix** (so `admin`→`admin11`, `kef`→`kefu`, `adm`→`adm1n`
all hit). Only consider `http`/`https` URLs (ignore `android://`,
`chrome-extension://`, etc.). Record the indicator, e.g. `subdomain:kef`,
`path:/admin`, `keyword:cn-admin`.

### Strong — prefix match (subdomain label or path segment starts with)
```
admin  adm  adminer  superadmin  webadmin  siteadmin  sysadmin
cpanel  phpmyadmin  backoffice  backstage  houtai  glht  wpadmin
kef  kefu  ador          ← scam-operation customer-service / admin backends
```

### Strong — exact label/segment
```
panel  cp  bo  backend  dashboard  dash  manage  manager  mgmt
console  control  controlpanel  master  administrator  superuser  root  godmode
agent  agents  daili  merchant  seller  cashier  finance  withdraw  deposit
recharge  wallet  gly  boss  operator  staff  pma
jenkins  grafana  kibana  portainer  wp-admin  wp-login
```

### Localized keywords (substring, any language)
```
管理   后台   代理   客服   administrador
(admin / backend / agent / customer-service / administrator)
```

### Contextual amplifiers (raise confidence, esp. in stealer logs)
- **Scam TLDs:** `.xyz .top .vip .online .club .cc .icu .shop .fun .sbs .lol`
- **Multi-agent pattern:** ≥3 distinct accounts on one non-mainstream domain
  → reseller/agent panel (e.g. a gambling back office).
- **Raw IP host** with a `/login`, `/index.php`, or panel path.

### Intentionally NOT flagged (noise control)
Generic `login` / `signin` / `auth` / `account` / `api` / `portal` on mainstream
hosts (e.g. `accounts.google.com`) — too common to be useful. They only matter
when combined with a scam TLD, multi-agent pattern, or raw-IP host.

---

## How the skill uses it

- **`/subdomain`, `/sweep`:** after enumerating subdomains, flag any matching the
  rules as **likely admin/sensitive** and prioritize them in findings + `/exposure`.
- **`/query`:** bias dork generation toward `inurl:admin`, `inurl:login`,
  `site:target -www`, and the prefixes above.
- **`/stealer-log`:** classify every recovered/visited URL; admin hits become the
  actor's infrastructure IOCs and drive victim-vs-operator triage.
- **Reporting:** list detected admin/sensitive endpoints as their own IOC block
  with the matched indicator, and export via `/report ioc`.
