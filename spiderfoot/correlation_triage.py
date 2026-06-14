# -------------------------------------------------------------------------------
# Name:         correlation_triage
# Purpose:      On-demand, metadata-only LLM triage of correlation results.
#               The deterministic correlation engine is not involved here.
# Licence:      MIT
# -------------------------------------------------------------------------------
import json
import logging
import os
import time

from spiderfoot.llm import OpenRouterClient, LLMError

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

    def build_payload(self, scan_id: str) -> list:
        """Build the metadata-only triage payload for a scan's correlations.

        Returns a list of dicts, one per correlation, in scanCorrelationList
        order, each carrying ONLY: index, rule name/description, risk, event
        count, and event-type names. No raw event values, no scan name, no
        target. The correlation title (``row[1]``) is deliberately excluded: it
        is generated from matched event data and routinely embeds raw values
        (e.g. a leaked email or host), so egressing it would breach the
        metadata-only contract.

        Args:
            scan_id (str): scan instance ID

        Returns:
            list: metadata-only dicts (one per correlation) safe for egress
        """
        correlations = self.dbh.scanCorrelationList(scan_id)
        payload = []
        for index, row in enumerate(correlations):
            corr_id = row[0]
            events = self.dbh.scanResultEvent(scan_id, correlationId=corr_id)
            event_types = sorted({e[4] for e in events})
            payload.append({
                "index": index,
                "rule_name": row[4],
                "rule_description": row[5],
                "risk": row[3],
                "event_count": row[7],
                "event_types": event_types,
            })
        return payload

    def validate_results(self, raw: dict, id_by_index: dict) -> list:
        """Validate an LLM response and map it back to correlation ids.

        Args:
            raw (dict): parsed LLM response (untrusted)
            id_by_index (dict): payload index -> correlation id

        Returns:
            list: validated dicts {correlation_id, priority, rank, explanation, grp}

        Raises:
            LLMError: response shape was unusable
        """
        if not isinstance(raw, dict) or not isinstance(raw.get("results"), list):
            raise LLMError("LLM response missing 'results' array")

        validated = []
        for item in raw["results"]:
            if not isinstance(item, dict):
                continue
            index = item.get("index")
            if index not in id_by_index:
                continue

            priority = str(item.get("priority", "INFO")).upper()
            if priority not in PRIORITIES:
                priority = "INFO"

            try:
                rank = int(item.get("rank", 0))
            except (TypeError, ValueError):
                rank = 0

            explanation = item.get("explanation")
            explanation = str(explanation)[:_MAX_EXPLANATION] if explanation is not None else None

            grp = item.get("group")
            grp = str(grp) if grp else None

            validated.append({
                "correlation_id": id_by_index[index],
                "priority": priority,
                "rank": rank,
                "explanation": explanation,
                "grp": grp,
            })
        return validated

    def triage(self, scan_id: str, now: int = None) -> dict:
        """Run on-demand LLM triage for a scan's correlations.

        Args:
            scan_id (str): scan instance ID
            now (int): epoch seconds to stamp results (defaults to time.time()).

        Returns:
            dict: {enabled, triaged, truncated, model}

        Raises:
            LLMError: the LLM call or its response was unusable (nothing stored).
        """
        if not self.is_enabled():
            self.log.info("LLM triage requested but feature is not configured.")
            return {"enabled": False, "triaged": 0, "truncated": False, "model": None}

        generated = int(now if now is not None else time.time())
        model = str(self.config.get("_llm_model") or "")
        if not model:
            raise LLMError("No LLM model configured")

        payload = self.build_payload(scan_id)

        # Map every payload index to its correlation id once (single query, taken
        # before any truncation/sort so the index->id mapping stays correct).
        correlations = self.dbh.scanCorrelationList(scan_id)
        id_by_index = {i: correlations[i][0] for i in range(len(correlations))}

        cap = int(self.config.get("_llm_max_correlations", 50))
        truncated = False
        total = len(payload)
        if total > cap:
            # Highest-risk first so the cap keeps the most important findings.
            order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
            payload.sort(key=lambda p: order.get(str(p.get("risk", "INFO")).upper(), 5))
            payload = payload[:cap]
            truncated = True
            self.log.info(f"LLM triage truncated to top {cap} correlations of {total}.")

        client = OpenRouterClient(
            api_key=self._resolve_api_key(),
            model=model,
            timeout=int(self.config.get("_llm_timeout", 120)),
            max_tokens=int(self.config.get("_llm_max_tokens", 4000)),
        )
        raw = client.chat(SYSTEM_PROMPT, json.dumps(payload))
        results = self.validate_results(raw, id_by_index)

        for r in results:
            self.dbh.correlationLlmCreate(
                r["correlation_id"], r["priority"], r["rank"],
                r["explanation"], r["grp"], model, generated,
            )

        self.log.info(f"LLM triage stored {len(results)} results for scan {scan_id}.")
        return {"enabled": True, "triaged": len(results), "truncated": truncated, "model": model}
