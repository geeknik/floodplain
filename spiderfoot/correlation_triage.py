# -------------------------------------------------------------------------------
# Name:         correlation_triage
# Purpose:      On-demand, metadata-only LLM triage of correlation results.
#               The deterministic correlation engine is not involved here.
# Licence:      MIT
# -------------------------------------------------------------------------------
import logging
import os

PRIORITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
_MAX_EXPLANATION = 500
_ENV_KEY = "FLOODPLAIN_OPENROUTER_API_KEY"

SYSTEM_PROMPT = (
    "You are a security analyst triaging OSINT correlation findings. "
    "You are given a JSON array of correlation findings (metadata only, no raw "
    "data). For each finding, assign a priority (one of CRITICAL, HIGH, MEDIUM, "
    "LOW, INFO), an overall rank (1 = most important), a one or two sentence "
    "plain-language explanation, and an optional group label for findings that "
    "are duplicates or closely related. Respond ONLY with a JSON object of the "
    'form {"results": [{"index": <int>, "priority": <str>, "rank": <int>, '
    '"explanation": <str>, "group": <str|null>}]}. Do not invent data.'
)


class CorrelationTriage:
    """Orchestrates on-demand LLM triage of a scan's correlation results."""

    log = logging.getLogger("spiderfoot.correlation_triage")

    def __init__(self, dbh, config: dict) -> None:
        """Initialise the triage orchestrator.

        Args:
            dbh: SpiderFootDb handle used to read correlations and persist results.
            config (dict): runtime configuration (LLM settings live under _llm_*).
        """
        self.dbh = dbh
        self.config = config or {}

    def _resolve_api_key(self) -> str:
        """Resolve the OpenRouter API key, preferring the environment variable.

        Returns:
            str: the API key, or an empty string if none is configured.
        """
        return os.environ.get(_ENV_KEY) or str(self.config.get("_llm_api_key") or "")

    def is_enabled(self) -> bool:
        """Report whether LLM triage is enabled and has a usable key.

        Returns:
            bool: True only when the feature flag is set and a key is resolvable.
        """
        return bool(self.config.get("_llm_enabled")) and bool(self._resolve_api_key())
