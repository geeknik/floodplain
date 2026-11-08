"""Deprecated compatibility alias for the ``floodplain`` package.

Floodplain's core package was renamed from ``spiderfoot`` to ``floodplain``.
This shim keeps third-party and private modules that still do
``from spiderfoot import SpiderFootPlugin`` (or import a submodule such as
``spiderfoot.db``) working: every name resolves to the *same* object in
``floodplain``, so isinstance checks and class identity are unchanged.

New code should import from ``floodplain``. This alias will be removed in a
future release.
"""

import importlib
import sys
import warnings

import floodplain
from floodplain import *  # noqa: F401,F403
from floodplain import __version__  # noqa: F401

warnings.warn(
    "The 'spiderfoot' package has been renamed to 'floodplain'; "
    "update imports to 'from floodplain import ...'.",
    DeprecationWarning,
    stacklevel=2,
)

_SUBMODULES = (
    "__version__", "correlation", "correlation_triage", "db", "event", "helpers",
    "llm", "logger", "plugin", "target", "threadpool", "websearch",
)

for _name in _SUBMODULES:
    _module = importlib.import_module(f"floodplain.{_name}")
    sys.modules[f"spiderfoot.{_name}"] = _module
    if _name != "__version__":  # keep the __version__ string, not the module
        setattr(sys.modules[__name__], _name, _module)

__all__ = [n for n in dir(floodplain) if not n.startswith("_")]
