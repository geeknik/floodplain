# test_readme_modules.py
"""Keep the README "MODULES / INTEGRATIONS" table in lockstep with modules/.

Every loadable module (except the ``sfp__*`` storage sinks) must have exactly
one README row, and every README row must correspond to such a module:

    external service  [<name>](<dataSource website>)|<summary>|<Free|Tiered|Commercial> API
    external tool     [<name>](<toolDetails website>)|<summary>|Tool
    internal          <name>|<summary>|Internal

Adding, removing, renaming or re-describing a module therefore fails CI until
the README is updated. Failure messages print the exact row(s) to add or
replace.
"""
import os
import unittest

from floodplain import SpiderFootHelpers

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
SECTION = "### MODULES / INTEGRATIONS"
TABLE_HEADER = "| Name     | Description | Type   |"

# dataSource 'model' -> README "Type" column.
MODEL_TYPE = {
    "FREE_NOAUTH_UNLIMITED": "Free API",
    "FREE_AUTH_UNLIMITED": "Free API",
    "FREE_NOAUTH_LIMITED": "Tiered API",
    "FREE_AUTH_LIMITED": "Tiered API",
    "COMMERCIAL_ONLY": "Commercial API",
    "PRIVATE_ONLY": "Commercial API",
}


def load_modules():
    """Load module metadata the same way the scanner does.

    Returns:
        dict: module file stem -> module info
    """
    mods = SpiderFootHelpers.loadModulesAsDict(os.path.join(ROOT, "modules"), ['sfp_template.py'])
    return {k: v for k, v in mods.items() if not k.startswith("sfp__")}


def render_row(mod):
    """Render the README row for one module.

    Args:
        mod (dict): module info from loadModulesAsDict

    Returns:
        str: README table row
    """
    meta = mod['meta']
    ds = meta.get('dataSource')
    tool = meta.get('toolDetails')
    if ds:
        return f"[{mod['name']}]({ds.get('website')})|{mod['descr']}|{MODEL_TYPE.get(ds.get('model'), '?')}"
    if tool:
        return f"[{mod['name']}]({tool.get('website')})|{mod['descr']}|Tool"
    return f"{mod['name']}|{mod['descr']}|Internal"


def expected_rows():
    """README rows derived from module metadata, keyed by module name.

    Returns:
        dict: module display name -> rendered README row
    """
    return {mod['name']: render_row(mod) for mod in load_modules().values()}


def row_name(row):
    """Extract the display name from a README row.

    Args:
        row (str): README table row

    Returns:
        str: module display name
    """
    first = row.split("|", 1)[0]
    if first.startswith("[") and "](" in first:
        return first[1:first.index("](")]
    return first


def table_bounds(lines):
    """Locate the module table body.

    Args:
        lines (list): README lines

    Returns:
        tuple: (first body line index, index one past the last body line)
    """
    start = lines.index(SECTION)
    header = lines.index(TABLE_HEADER, start)
    first = header + 2  # skip the alignment row
    end = first
    while end < len(lines) and lines[end].strip():
        end += 1
    return first, end


def readme_rows():
    """Rows currently in the README module table, in file order.

    Returns:
        list: (display name, full row line) tuples
    """
    with open(os.path.join(ROOT, "README.md"), encoding="utf-8") as f:
        lines = f.read().split("\n")
    first, end = table_bounds(lines)
    return [(row_name(line), line) for line in lines[first:end]]


class TestReadmeModules(unittest.TestCase):

    def test_every_module_has_an_exact_readme_row(self):
        expected = expected_rows()
        actual = dict(readme_rows())
        problems = []
        for name, row in sorted(expected.items(), key=lambda kv: kv[0].lower()):
            if name not in actual:
                problems.append(f"MISSING README row:\n    {row}")
            elif actual[name] != row:
                problems.append(f"OUTDATED README row:\n    have: {actual[name]}\n    want: {row}")
        self.assertFalse(problems, "README module table is out of sync with modules/:\n" + "\n".join(problems))

    def test_every_readme_row_maps_to_an_existing_module(self):
        expected = expected_rows()
        stale = [name for name, _ in readme_rows() if name not in expected]
        self.assertFalse(stale, f"README lists modules that no longer exist (remove these rows): {stale}")

    def test_readme_rows_are_unique_and_sorted(self):
        names = [name for name, _ in readme_rows()]
        dups = sorted({n for n in names if names.count(n) > 1})
        self.assertFalse(dups, f"Duplicate README rows: {dups}")
        self.assertEqual(names, sorted(names, key=str.lower), "README module rows must be sorted case-insensitively")

    def test_every_model_maps_to_a_readme_type(self):
        unknown = sorted({m['meta']['dataSource'].get('model') for m in load_modules().values()
                          if m['meta'].get('dataSource')} - set(MODEL_TYPE))
        self.assertFalse(unknown, f"Add these dataSource models to MODEL_TYPE: {unknown}")

    def test_module_count_claim_is_not_overstated(self):
        with open(os.path.join(ROOT, "README.md"), encoding="utf-8") as f:
            text = f.read()
        count = len(load_modules())
        for claim in ("over 200 modules", "200+ modules"):
            if claim in text:
                self.assertGreater(count, 200, f"README claims '{claim}' but only {count} modules exist")
