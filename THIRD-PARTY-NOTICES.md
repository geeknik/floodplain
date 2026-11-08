# Third-party notices

Floodplain's own code is MIT-licensed (see [LICENSE](LICENSE), which also
carries the MIT notice for SpiderFoot, from which Floodplain is forked —
SpiderFoot was relicensed from GPL-2.0 to MIT by its author on 2022-05-06, and
Floodplain's history descends from that commit).

The repository also redistributes the following third-party components. Each
keeps its own license; the full text is included next to the component.

## Web UI libraries (`floodplain/static/node_modules/`)

| Component | Version | License | License text |
|---|---|---|---|
| jQuery | 3.7.1 | MIT | `jquery/LICENSE.txt` |
| Bootstrap | 3.4.1 | MIT | `bootstrap/LICENSE` |
| D3 | 3.5.17 | BSD-3-Clause | `d3/LICENSE` |
| sigma.js | 1.2.1 | MIT | `sigma/LICENSE.txt` |
| TableSorter (FORK) | 2.31.3 | MIT (dual MIT/GPL; used under MIT) | `tablesorter/LICENSE` |

AlertifyJS (GPL-3.0) was removed on 2026-11-07 and replaced by Floodplain's
own `floodplain/static/js/floodplain.notify.js` (MIT), so that every component
shipped with the web UI is under a permissive license.

## Data files

| Component | License | License text |
|---|---|---|
| ispell word lists (`floodplain/dicts/ispell/*.dict`) | BSD-style (Geoff Kuenning) | `floodplain/dicts/ispell/LICENSE` |

## Artwork

The Floodplain logo and icons (`floodplain/static/img/floodplain-*.png`) are
original artwork for this project, released under the project's MIT license.
The wordmark is set in Lato (SIL Open Font License 1.1); the font itself is
not redistributed.

## Not distributed in this repository

Python dependencies (`requirements.txt`) are installed from PyPI under their
own licenses. The external tools that `Dockerfile.full` downloads (Nuclei,
TruffleHog, testssl.sh, WhatWeb, CMSeeK, nmap, wafw00f, dnstwist,
snallygaster, retire.js, ...) are fetched at build time under their own
licenses, several of which are GPL or (for nmap) the Nmap Public Source
License. If you **publish a built `Dockerfile.full` image**, you are
redistributing those tools and must comply with their licenses (for GPL
tools, provide the corresponding source; review the NPSL's terms for nmap).
