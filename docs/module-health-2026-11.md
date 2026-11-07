# Module Health Sweep — 2026-11-07

Floodplain inherited 232 modules from SpiderFoot 4.0 (2022). This
sweep checks which third-party services those modules depend on are still
alive, migrated, retiring, or dead, and records the action taken.

## Summary

| Verdict | Modules | Action |
|---|---|---|
| **Dead** | 26 | Removed in this commit |
| **Retiring** (shutdown announced) | 5 | Replace before cutoff (Google CSE: **2027-01-01**) |
| **Migrated / needs a fix** | 5 | Fixed 2026-11-07 (see below) |
| **Watch** (ambiguous) | 5 | Keep; re-check next sweep |
| **Answering** (host up) | ~138 | Keep — reachability only, not deep API validation |

## Method

1. **Extraction.** Parsed every module's AST for the URLs it calls (excluding
   documentation URLs in `meta`), plus the real endpoints behind the shared
   `sflib` helpers (`googleIterate`, `bingIterate`). 179 modules, 190 hosts.
2. **Reachability probe.** DNS + TLS + HTTP against each host.
   *Caveat:* the build sandbox's resolver silently blocks non-allowlisted
   domains, so sandbox DNS failures were **not** treated as evidence. Every
   failure was re-checked against authoritative DNS (Google DoH) from an
   independent vantage point. That re-check overturned five false "dead"
   results (ipstack, SEON, AbstractAPI, MultiProxy's domain, Ahmia).
3. **Shutdown research.** Services that answer at the network level can still
   be discontinued (e.g. Bing Search API). Each suspect was verified by a
   direct endpoint probe and/or an official announcement. "Unknown" was used
   rather than guessing. The most consequential claims (Google CSE date,
   ThreatJammer hijack, Ahmia status) were independently re-verified.

A 401/403/404 on an API root is normal and was **not** counted as death.

## ⚠️ Security findings

Several dead services' domains are now controlled by third parties. Any
Floodplain install with these modules enabled was sending scan targets (and,
where configured, API keys) to infrastructure the original operator no longer
controls:

| Module | Finding |
|---|---|
| `sfp_threatjammer` | `threatjammer.com` **taken over** by an Indonesian gambling operation (verified 2026-11-07). Target IPs and the user's API key were going to it. |
| `sfp_crobat_api` | Parent domain `omnisint.io` now redirects to gambling spam; whoever holds it controls `sonar.omnisint.io`. |
| `sfp_threatcrowd` | `www.threatcrowd.org` is a CNAME to a **deleted AWS load balancer** — dangling DNS, claimable by anyone. |
| `sfp_punkspider` | `api.punkspider.org` is a CNAME to a **deleted AWS load balancer** — same risk. |
| `sfp_riskiq` | `api.passivetotal.org` now aliases an unrelated CDN host; API keys were being sent to a non-API endpoint. |
| `sfp_callername` | Domain parked (GoDaddy cash-parking NS). |

Every NXDOMAIN domain below is a latent version of the same risk: if someone
re-registers it, the module would start sending them data. That is the main
reason dead modules are removed rather than left disabled.

## Removed (26)

| Module | Evidence | Source |
|---|---|---|
| `sfp_bgpview` | `api.bgpview.io` NXDOMAIN | Authoritative DNS |
| `sfp_binaryedge` | All accounts shut down 2025-03-31 | [Coalition FAQ](https://help.coalitioninc.com/hc/en-us/articles/34383910057371-BinaryEdge-Transition-FAQ) |
| `sfp_bingsearch` | Bing Search APIs retired 2025-08-11 | [Microsoft Learn](https://learn.microsoft.com/en-us/lifecycle/announcements/bing-search-api-retirement) |
| `sfp_bingsharedip` | Bing Search APIs retired 2025-08-11 | [Microsoft Learn](https://learn.microsoft.com/en-us/lifecycle/announcements/bing-search-api-retirement) |
| `sfp_botvrij` | Blocklist frozen (Last-Modified 2021-10-06) | Direct probe |
| `sfp_callername` | Domain parked | Direct probe |
| `sfp_coinblocker` | Project gone private (GitLab 404; Pages login wall) | Direct probe |
| `sfp_crobat_api` | API taken offline after Rapid7 revoked dataset access; domain hijacked | [SonarSearch README](https://raw.githubusercontent.com/Cgboal/SonarSearch/master/readme.md) |
| `sfp_crxcavator` | `api.crxcavator.io` NXDOMAIN | Authoritative DNS |
| `sfp_dnsgrep` | `dns.bufferover.run` NXDOMAIN | Authoritative DNS |
| `sfp_emailcrawlr` | `api.emailcrawlr.com` NXDOMAIN | Authoritative DNS |
| `sfp_fsecure_riddler` | `riddler.io` parked (SOA `withsecure.parked.domain`) | Authoritative DNS |
| `sfp_multiproxy` | Proxy list URL now redirects to a bare contact page | Direct probe |
| `sfp_onioncity` | `onion.link` NXDOMAIN; also depends on retiring Google CSE | Direct probe |
| `sfp_punkspider` | Dangling CNAME to deleted AWS ELB | Authoritative DNS |
| `sfp_riskiq` | PassiveTotal API host now a CDN alias returning "Page not found"; TI folded into Defender XDR | Direct probe; [Microsoft Learn](https://learn.microsoft.com/en-us/defender-xdr/defender-threat-intelligence) |
| `sfp_sorbs` | Proofpoint shut SORBS down 2024-06-05; `sorbs.net` NXDOMAIN | [The Register](https://www.theregister.com/2024/06/07/sorbs_closed) |
| `sfp_spyonweb` | Connection refused on 80/443; no notice found | Direct probe |
| `sfp_sublist3r` | Backend does not answer even past TLS; no notice found | Direct probe |
| `sfp_threatcrowd` | Dangling CNAME to deleted AWS ELB | Authoritative DNS |
| `sfp_threatjammer` | Domain hijacked (gambling spam) | Direct probe |
| `sfp_threatminer` | Cloudflare 522 (origin unreachable) on all hosts; no notice found | Direct probe |
| `sfp_trashpanda` | `api.got-hacked.wtf` NXDOMAIN | Authoritative DNS |
| `sfp_trumail` | Endpoint returns "Trumail has joined Emailable" (HTTP 200) | Direct probe |
| `sfp_twitter` | X requires login; module's pre-2019 HTML regexes no longer match | Direct probe |
| `sfp_zonefiles` | Lame delegation (authoritative NS refuse the zone) | Authoritative DNS |

Note: three removals (`sfp_threatminer`, `sfp_sublist3r`, `sfp_spyonweb`) have
no shutdown announcement; they are removed on sustained unreachability. Restore
from git history if a service returns.

## Retiring — replace before cutoff

| Module | Status | Deadline |
|---|---|---|
| `sfp_googlesearch` | Google Custom Search JSON API closed to new customers. **Successor `sfp_bravesearch` added 2026-11-07.** Delete this module after the cutoff. | **2027-01-01** ([Google](https://developers.google.com/custom-search/v1/overview)) |
| `sfp_pastebin` | **Migrated 2026-11-07** to the shared `spiderfoot.websearch` interface: Brave (`brave_api_key`) preferred, legacy Google key honoured until the cutoff. | **2027-01-01** (Google path only) |
| `sfp_socialprofiles` | **Migrated 2026-11-07**: `method` defaults to `brave`; dead Bing path and dead Google+ site removed. | **2027-01-01** (Google path only) |
| `sfp_clearbit` | No new Clearbit subscriptions or free accounts (HubSpot) | No date; unusable for new users ([Clearbit](https://help.clearbit.com/hc/en-us/articles/20717192156695-How-Can-I-Buy-Clearbit)) |
| `sfp_cybercrimetracker` | Feed still served but last entry 2023-12-30 | Stale |

**Done 2026-11-07:** `spiderfoot/websearch.py` provides one provider
interface (Brave Search; Google Custom Search until its cutoff). Each provider
has its own key option, so an existing Google key is never sent to Brave.
Queries are now URL-encoded (the old `googleIterate` only escaped spaces, so a
`&` in a search string could inject parameters), result hosts are matched on a
subdomain boundary (previously `evilexample.com` counted as `example.com` and
`evilpastebin.com` pages were fetched), and profile pages are fetched with TLS
verification. `sflib.googleIterate`/`bingIterate` were removed. After
2027-01-01: delete `GoogleCustomSearch`, `sfp_googlesearch` and the legacy
Google options.

## Migrated / needs a fix — fixed 2026-11-07

| Module | Fix applied |
|---|---|
| `sfp_phishstats` | Moved to `https://api.phishstats.info/api/phishing`; optional `X-API-Key` header (anonymous: 50 req/day/IP). IP validated before it enters PhishStats' `_where` filter syntax (blocks `~or(...)` injection); netblock expansion IPv4-only and size-bounded; 401/403/429 stop the module; self-throttled to the published 20 req/min. Model now `FREE_NOAUTH_LIMITED`. |
| `sfp_emailrep` | API key now mandatory (unauthenticated API disabled). Email validated and URL-encoded before it is placed in the request path (previously raw concatenation allowed path injection with the key header attached). |
| `sfp_nameapi` | `http://` → `https://` (the key is a query parameter and was sent in cleartext). Email validated and URL-encoded; verdict allow-listed; results de-duplicated. |
| `sfp_bitcoinabuse` | **Replaced by `sfp_chainabuse`** (TRM Labs Chainabuse API, HTTP Basic auth). Free keys allow 10 calls/month, so lookups are capped per scan (`max_queries`, default 5) and de-duplicated. Only a structured summary is emitted; reporters' free-text descriptions, losses, evidence and IPs are discarded. Bitcoin only for now — Ethereum needs a `MALICIOUS_ETHEREUM_ADDRESS` event type plus an event-type migration for existing databases. |
| `sfp_koodous` | 401 *and* 403 treated as missing/invalid key. Also fixed: a "no results" 404 disabled the module for the rest of the scan; `results: null` crashed it; untrusted `sha256`/app name were embedded raw in `<SFURL>` markup; pagination now hard-capped at 50 pages with a validated cursor. |

Cross-cutting fix found during this work: `sflib.removeUrlCreds()` passed
`re.IGNORECASE` as the positional `count` argument, so redaction was
case-sensitive and `apiKey=` (NameAPI) was written to the logs on every
request. Five `fetchUrl` error paths also logged raw URLs and tracebacks.
Redaction is now case-insensitive, covers userinfo and common key names
(`key`, `apiKey`, `access_key`, `api_token`, `auth`, `sig`, `session_id`, ...),
is linear-time, and is applied to every `fetchUrl` log line and exception
message.

## Watch list (keep; re-check next sweep)

| Module | Observation |
|---|---|
| `sfp_h1nobbdde` | HTTP 500 since ~2026-08; worked in Aug 2026 Wayback snapshot. |
| `sfp_onionsearchengine` | Cloudflare bot block (403) — not proof of death. |
| `sfp_ahmia` | Domain live (NS `dns1/dns2.xnet.fi`); search page returned an empty body to automated fetches. |
| `sfp_torch` | Onion-only; cannot verify without Tor. |
| `sfp_greensnow` | Per-IP view shows years-old data; bulk `greensnow.txt` blocklist is current — consider switching. |

## Replacement opportunities

- **BGP/ASN data** (replaces `sfp_bgpview`): RIPEstat Data API — free, keyless.
- **Passive DNS / subdomains** (replaces `sfp_dnsgrep`, `sfp_crobat_api`):
  AlienVault OTX passive DNS, HackerTarget hostsearch.
- **Web search** (replaces Bing + Google CSE): Brave Search API or SerpAPI.

## Re-running

Repeat this sweep at least every release. Treat sandbox DNS failures as
unverified until confirmed by authoritative DNS from an independent network.
