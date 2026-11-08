#!/usr/bin/env python3
"""Point Floodplain's tool modules at the binaries bundled in Dockerfile.full.

Runs at container start, before the web UI. Only options that are unset (or
still empty) are written, so paths changed by the user in the web UI persist
across restarts. Uses the same data directory and database file resolution as
sf.py (FLOODPLAIN_DATA, then legacy names), so it always configures the
database Floodplain actually opens.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from floodplain import SpiderFootDb, SpiderFootHelpers  # noqa: E402

TOOLS_VENV = "/opt/tools-venv/bin"

TOOL_PATHS = {
    "sfp_tool_cmseek:pythonpath": f"{TOOLS_VENV}/python",
    "sfp_tool_cmseek:cmseekpath": "/tools/CMSeeK/cmseek.py",
    "sfp_tool_dnstwist:pythonpath": f"{TOOLS_VENV}/python",
    "sfp_tool_dnstwist:dnstwistpath": f"{TOOLS_VENV}/dnstwist",
    "sfp_tool_nbtscan:nbtscan_path": "/usr/bin/nbtscan",
    "sfp_tool_nuclei:nuclei_path": "/tools/nuclei",
    "sfp_tool_nuclei:template_path": "/tools/nuclei-templates",
    "sfp_tool_onesixtyone:onesixtyone_path": "/usr/bin/onesixtyone",
    "sfp_tool_retirejs:retirejs_path": "/usr/local/bin/retire",
    "sfp_tool_snallygaster:snallygaster_path": f"{TOOLS_VENV}/snallygaster",
    "sfp_tool_testsslsh:testsslsh_path": "/tools/testssl.sh/testssl.sh",
    "sfp_tool_trufflehog:trufflehog_path": "/tools/trufflehog",
    "sfp_tool_wafw00f:python_path": f"{TOOLS_VENV}/python",
    "sfp_tool_wafw00f:wafw00f_path": f"{TOOLS_VENV}/wafw00f",
    "sfp_tool_whatweb:whatweb_path": "/tools/WhatWeb/whatweb",
    # nmap needs raw sockets (root) to be useful; the image runs unprivileged.
    "sfp_tool_nmap:nmappath": "DISABLED_BECAUSE_NMAP_REQUIRES_ROOT_TO_WORK",
}


def main() -> int:
    """Write default tool paths into the Floodplain database.

    Returns:
        int: process exit code
    """
    db_path = SpiderFootHelpers.dataFile("floodplain.db", "spiderfoot.db")
    dbh = SpiderFootDb({"__database": db_path})
    current = dbh.configGet() or {}
    missing = {k: v for k, v in TOOL_PATHS.items() if not current.get(k)}
    if missing:
        dbh.configSet(missing)
    print(f"Configured {len(missing)} tool path(s) in {db_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
