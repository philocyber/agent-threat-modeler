"""Robust multi-strategy JSON extraction and threat-finding from LLM responses."""

from __future__ import annotations

import json
import logging
import re

from pydantic import BaseModel as PydanticBaseModel, ValidationError

from agentictm.agents.reflection import _strip_think_tags

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# JSON extraction — robust multi-strategy parser
# ---------------------------------------------------------------------------

def _fix_common_json_issues(s: str) -> str:
    """Fix common LLM JSON generation issues.

    Handles trailing commas, JS-style comments, unquoted keys, unquoted
    simple-word values, missing commas between adjacent objects,
    orphaned bare strings inside objects, and ``key: value`` pairs where
    the value is an unquoted identifier (common VLM output like
    ``id: CloudFront``).
    """
    s = re.sub(r",\s*([}\]])", r"\1", s)
    s = re.sub(r"//[^\n]*", "", s)
    s = re.sub(r"/\*.*?\*/", "", s, flags=re.DOTALL)
    s = re.sub(r'(?<="),\s*"[^"]{0,200}"\s*(?=,\s*"[^"]*"\s*:)', ',', s)
    s = re.sub(r"(?<=[{,])\s*(\w+)\s*:", r' "\1":', s)
    s = re.sub(
        r'(:\s*)([A-Za-z_][\w.]*)\s*([,}\]\n])',
        lambda m: m.group(1) + '"' + m.group(2) + '"' + m.group(3),
        s,
    )
    s = re.sub(r"\}\s*\{", "},{", s)
    return s


def _repair_truncated_json(s: str) -> str | None:
    """Attempt to repair JSON truncated by LLM token limits.

    Walks through the string tracking brace depth and finds the last
    complete ``}`` at any depth above 0. Truncates there and closes
    all remaining open brackets/braces.
    """
    last_good = -1
    depth = 0
    in_string = False
    escape = False
    for i, ch in enumerate(s):
        if escape:
            escape = False
            continue
        if ch == '\\' and in_string:
            escape = True
            continue
        if ch == '"' and not escape:
            in_string = not in_string
            continue
        if in_string:
            continue
        if ch == '{':
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth >= 1:
                last_good = i
    if last_good > 0:
        truncated = s[:last_good + 1]
        open_brackets = truncated.count('[') - truncated.count(']')
        open_braces = truncated.count('{') - truncated.count('}')
        repair = truncated + (']' * max(0, open_brackets)) + ('}' * max(0, open_braces))
        return repair
    return None


def _try_parse(s: str) -> dict | list | None:
    """Try parsing a string as JSON, with and without fixes."""
    for label, candidate_str in [("raw", s), ("fixed", _fix_common_json_issues(s))]:
        try:
            return json.loads(candidate_str)
        except json.JSONDecodeError as e:
            logger.debug("[JSON parse] %s attempt failed: %s (pos %d)", label, e.msg, e.pos)
    repaired = _repair_truncated_json(s)
    if repaired:
        for label, candidate_str in [("repaired", repaired), ("repaired+fixed", _fix_common_json_issues(repaired))]:
            try:
                return json.loads(candidate_str)
            except json.JSONDecodeError as e:
                logger.debug("[JSON parse] %s attempt failed: %s (pos %d)", label, e.msg, e.pos)
    try:
        from json_repair import repair_json
        fixed = repair_json(s, return_objects=True)
        if isinstance(fixed, (dict, list)):
            logger.info("[JSON parse] json-repair library succeeded")
            return fixed
    except Exception as exc:
        logger.debug("[JSON parse] json-repair failed: %s", exc)
    return None


def _extract_individual_json_objects(text: str) -> list[dict]:
    """Last-resort extraction: find individual JSON objects in malformed text.

    When the outer JSON structure is broken (truncated, malformed keys, etc.),
    this finds all complete {...} blocks that look like threat entries.
    """
    threat_keys = {"id", "title", "description", "name", "component",
                   "leaf_action", "stride_category", "attack_scenario",
                   "severity", "impact", "mitigation"}
    results: list[dict] = []
    depth = 0
    in_string = False
    escape = False
    obj_start = -1

    for i, ch in enumerate(text):
        if escape:
            escape = False
            continue
        if ch == '\\' and in_string:
            escape = True
            continue
        if ch == '"' and not escape:
            in_string = not in_string
            continue
        if in_string:
            continue
        if ch == '{':
            if depth == 2:
                obj_start = i
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 2 and obj_start >= 0:
                candidate = text[obj_start:i + 1]
                try:
                    obj = json.loads(candidate)
                    if isinstance(obj, dict) and (set(obj.keys()) & threat_keys):
                        results.append(obj)
                except json.JSONDecodeError:
                    fixed = _fix_common_json_issues(candidate)
                    try:
                        obj = json.loads(fixed)
                        if isinstance(obj, dict) and (set(obj.keys()) & threat_keys):
                            results.append(obj)
                    except json.JSONDecodeError:
                        pass
                obj_start = -1

    if not results:
        depth = 0
        in_string = False
        escape = False
        obj_start = -1
        for i, ch in enumerate(text):
            if escape:
                escape = False
                continue
            if ch == '\\' and in_string:
                escape = True
                continue
            if ch == '"' and not escape:
                in_string = not in_string
                continue
            if in_string:
                continue
            if ch == '{':
                if depth == 1:
                    obj_start = i
                depth += 1
            elif ch == '}':
                depth -= 1
                if depth == 1 and obj_start >= 0:
                    candidate = text[obj_start:i + 1]
                    try:
                        obj = json.loads(candidate)
                        if isinstance(obj, dict) and (set(obj.keys()) & threat_keys):
                            results.append(obj)
                    except json.JSONDecodeError:
                        fixed = _fix_common_json_issues(candidate)
                        try:
                            obj = json.loads(fixed)
                            if isinstance(obj, dict) and (set(obj.keys()) & threat_keys):
                                results.append(obj)
                        except json.JSONDecodeError:
                            pass
                    obj_start = -1

    return results


def extract_json_from_response(text: str | list) -> dict | list | None:
    """Robust multi-strategy JSON extraction from LLM responses.

    Strategies (in order):
    1. Strip <think> tags from reasoning models
    2. Find ```json code blocks
    3. Try parsing entire cleaned text
    4. Extract first { } or [ ] balanced block
    5. Fix common JSON issues and retry all above
    """
    if isinstance(text, list):
        parts = []
        for block in text:
            if isinstance(block, dict) and block.get("type") == "text":
                parts.append(block.get("text", ""))
            elif isinstance(block, str):
                parts.append(block)
        text = "\n".join(parts)
    if not isinstance(text, str):
        text = str(text) if text else ""
    if not text or not text.strip():
        logger.warning("Empty response from agent")
        return None

    cleaned = _strip_think_tags(text)
    if not cleaned:
        cleaned = text

    for candidate in [cleaned, text]:
        match_greedy = re.search(r"```(?:json)?\s*\n?(.*)\n?\s*```", candidate, re.DOTALL)
        if match_greedy:
            result = _try_parse(match_greedy.group(1).strip())
            if result is not None:
                return result

        match = re.search(r"```(?:json)?\s*\n?(.*?)\n?\s*```", candidate, re.DOTALL)
        if match:
            result = _try_parse(match.group(1).strip())
            if result is not None:
                return result

        code_start = re.search(r"```(?:json)?\s*\n", candidate)
        if code_start:
            block = candidate[code_start.end():].rstrip("`").strip()
            for sc, ec in [("{", "}"), ("[", "]")]:
                si = block.find(sc)
                ei = block.rfind(ec)
                if si != -1 and ei != -1 and ei > si:
                    result = _try_parse(block[si : ei + 1])
                    if result is not None:
                        return result

        result = _try_parse(candidate.strip())
        if result is not None:
            return result

        for start_char, end_char in [("{", "}"), ("[", "]")]:
            start = candidate.find(start_char)
            end = candidate.rfind(end_char)
            if start != -1 and end != -1 and end > start:
                result = _try_parse(candidate[start : end + 1])
                if result is not None:
                    return result

    logger.warning("Could not extract JSON from agent response")
    logger.info("Full agent response:\n%s", cleaned if cleaned else text)
    return None


def parse_structured_response(
    text: str,
    model: type[PydanticBaseModel],
    *,
    many: bool = False,
) -> PydanticBaseModel | list[PydanticBaseModel] | None:
    """Parse LLM response into Pydantic model(s) with fallback chain (I03).

    Fallback chain:
    1. Extract JSON via ``extract_json_from_response``
    2. Validate extracted JSON against the Pydantic *model*
    3. If ``many=True``, expect a list of items; each item is validated individually

    Returns a validated Pydantic model instance (or list if *many*), or ``None``
    on failure.  Invalid items in a list are silently skipped (logged).
    """
    raw = extract_json_from_response(text)
    if raw is None:
        return None

    try:
        if many:
            items_raw: list[dict] = []
            if isinstance(raw, list):
                items_raw = raw
            elif isinstance(raw, dict):
                for key in ("threats", "items", "results", "data"):
                    if key in raw and isinstance(raw[key], list):
                        items_raw = raw[key]
                        break
                else:
                    items_raw = [raw]

            validated: list[PydanticBaseModel] = []
            for idx, item in enumerate(items_raw):
                try:
                    validated.append(model.model_validate(item))
                except ValidationError as ve:
                    logger.warning("Structured parse: item %d failed validation: %s", idx, ve)
            return validated if validated else None

        else:
            if isinstance(raw, dict):
                return model.model_validate(raw)
            elif isinstance(raw, list) and raw:
                return model.model_validate(raw[0])
            return None

    except ValidationError as ve:
        logger.warning("Structured parse failed for %s: %s", model.__name__, ve)
        return None


# ---------------------------------------------------------------------------
# Generic threat-list finder for flexible JSON structures
# ---------------------------------------------------------------------------

_COMMON_THREAT_KEYS = [
    "threats", "threat_model", "threat_assessments", "identified_threats",
    "threat_analysis", "findings", "vulnerabilities", "attack_scenarios",
    "assessments", "results", "analysis",
]

_THREAT_DICT_KEYS = {
    "id", "title", "description", "threat", "severity", "component",
    "leaf_action", "stride_category", "impact", "mitigation",
    "name", "category", "attack_path", "confidence_score",
}


def _looks_like_threat_list(lst: list) -> bool:
    """Heuristic: list of dicts with at least one threat-like key."""
    if not lst or not isinstance(lst[0], dict):
        return False
    sample_keys = set(lst[0].keys())
    return bool(sample_keys & _THREAT_DICT_KEYS)


def find_threats_in_json(parsed: dict | None) -> list[dict]:
    """Recursively search a parsed JSON dict for a list of threat-like dicts.

    Handles varying LLM key names (threats, threat_model, findings, etc.)
    and nested structures (e.g. attack_trees[].threats[], threat_analysis.stage_4_threats[]).
    """
    if not isinstance(parsed, dict):
        return []

    for key in _COMMON_THREAT_KEYS:
        val = parsed.get(key)
        if isinstance(val, list) and _looks_like_threat_list(val):
            return _ensure_descriptions(val)

    for key in _COMMON_THREAT_KEYS:
        val = parsed.get(key)
        if isinstance(val, dict):
            found = find_threats_in_json(val)
            if found:
                return found

    best: list[dict] = []
    for _key, val in parsed.items():
        if isinstance(val, list) and _looks_like_threat_list(val):
            if len(val) > len(best):
                best = val
        elif isinstance(val, dict):
            found = find_threats_in_json(val)
            if found and len(found) > len(best):
                best = found

    if best:
        return _ensure_descriptions(best)

    for _key, val in parsed.items():
        if isinstance(val, list) and val and isinstance(val[0], dict):
            collected: list[dict] = []
            for item in val:
                if isinstance(item, dict):
                    sub_threats = find_threats_in_json(item)
                    collected.extend(sub_threats)
            if collected:
                return _ensure_descriptions(collected)

    return []


def _ensure_descriptions(threats: list[dict]) -> list[dict]:
    """Guarantee every threat dict has a non-empty 'description' field."""
    _DESC_FALLBACKS = (
        "attack_scenario", "threat", "vulnerability", "scenario",
        "title", "name", "attack_path",
    )
    for t in threats:
        if not t.get("description"):
            for key in _DESC_FALLBACKS:
                val = t.get(key)
                if val and isinstance(val, str) and len(val.strip()) > 10:
                    t["description"] = val.strip()
                    break
    return threats
