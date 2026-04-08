"""Semantic deduplication of threat lists (intra- and cross-component)."""

from __future__ import annotations

import logging
import re

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Deduplication constants
# ---------------------------------------------------------------------------

_SECURITY_TERMS = frozenset({
    "sql", "xss", "dos", "rce", "lfi", "rfi", "ssrf", "idor", "csrf", "jwt",
    "tls", "mtls", "mfa", "rbac", "iam", "oauth", "imap", "smtp",
    "injection", "inyección", "inyeccion", "bypass", "overflow", "exfiltration",
    "privilege", "escalation", "hijack", "spoofing", "tampering", "repudiation",
    "disclosure", "sanitization", "validation", "authentication",
})


_ATTACK_CONCEPT_GROUPS = [
    {"sql", "injection", "inyección", "inyeccion", "database", "datos"},
    {"session", "sesión", "sesion", "cookie", "hijack", "admin"},
    {"file", "archivo", "mime", "extension", "sanitiz", "upload"},
    {"poll", "polling", "flood", "rate", "limit", "dos", "brut"},
    {"oauth", "token", "credential", "credencial", "secret", "secreto"},
    {"privilege", "escalat", "elevaci", "rbac", "permis"},
    {"log", "audit", "auditoría", "repudi", "trazab", "forens"},
    {"xss", "script", "render", "html", "content"},
]

_DEDUP_SIMILARITY_THRESHOLD = 0.25
_CROSS_GROUP_SIMILARITY_THRESHOLD = 0.28


def _tokenize(text: str) -> set[str]:
    """Extract a bag of meaningful tokens from text for similarity comparison."""
    tokens = set(re.findall(r"[a-záéíóúñü]{3,}", text.lower()))
    _STOP = {"the", "and", "for", "that", "this", "with", "from", "can", "are",
             "una", "del", "que", "los", "las", "para", "por", "con", "como",
             "ser", "está", "este", "esta", "uno", "más", "not", "but"}
    return tokens - _STOP


def _weighted_jaccard(a: set[str], b: set[str]) -> float:
    """Jaccard with double weight for security-specific terms and a concept-group bonus."""
    if not a or not b:
        return 0.0
    intersection = a & b
    union = a | b
    sec_bonus = len(intersection & _SECURITY_TERMS)

    concept_bonus = 0.0
    for group in _ATTACK_CONCEPT_GROUPS:
        a_hits = len(a & group)
        b_hits = len(b & group)
        if a_hits >= 1 and b_hits >= 1:
            concept_bonus += 0.10

    base_sim = (len(intersection) + sec_bonus) / (len(union) + sec_bonus)
    return min(1.0, base_sim + concept_bonus)


def _jaccard(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def _normalize_component(comp: str) -> str:
    """Normalize component name for grouping: strip parentheticals, lowercase, trim."""
    comp = (comp or "").strip().lower()
    comp = re.sub(r"\(.*?\)", "", comp).strip()
    comp = re.sub(r"\s+", " ", comp)
    for noise in ("módulo de ", "modulo de ", "servicio de ", "capa "):
        comp = comp.replace(noise, "")
    return comp[:50]


def _merge_cluster(threats: list[dict], cluster_indices: list[int]) -> dict:
    """Merge a cluster of duplicate threats: keep richest description, combine metadata."""
    group = [threats[idx] for idx in cluster_indices]
    best = max(group, key=lambda t: len(t.get("description") or ""))
    best = dict(best)
    methodologies = {t.get("methodology", "") for t in group if t.get("methodology")}
    if len(methodologies) > 1:
        best["methodology"] = ", ".join(sorted(methodologies))
    if not best.get("mitigation"):
        for t in group:
            if t.get("mitigation"):
                best["mitigation"] = t["mitigation"]
                break
    if not best.get("control_reference"):
        for t in group:
            if t.get("control_reference"):
                best["control_reference"] = t["control_reference"]
                break
    if not (best.get("component") or "").strip():
        for t in group:
            if (t.get("component") or "").strip():
                best["component"] = t["component"]
                break
    return best


_SAME_STRIDE_INTRA_THRESHOLD = 0.22
_LENGTH_DIFF_PENALTY_THRESHOLD = 0.60


def _deduplicate_threats(threats: list[dict]) -> list[dict]:
    """Two-pass semantic deduplication.

    Pass 1: Group by normalized component, merge within groups
            (weighted Jaccard >= 0.22 for same-STRIDE pairs, >= 0.25 otherwise).
    Pass 2: Cross-group dedup for threats with the same STRIDE category,
            using a higher threshold (weighted Jaccard >= 0.28) to catch the
            same vulnerability described under different component names.
    """
    # ── Pass 1: intra-component dedup ──
    comp_groups: dict[str, list[int]] = {}
    for i, t in enumerate(threats):
        key = _normalize_component(t.get("component", ""))
        comp_groups.setdefault(key, []).append(i)

    merged_indices_p1: set[int] = set()
    pass1_winners: list[dict] = []

    for _comp_key, indices in comp_groups.items():
        if len(indices) == 1:
            pass1_winners.append(threats[indices[0]])
            continue

        token_cache = {}
        for idx in indices:
            token_cache[idx] = _tokenize(threats[idx].get("description", ""))

        local_clusters: list[list[int]] = []
        assigned: set[int] = set()

        for i_pos, i_idx in enumerate(indices):
            if i_idx in assigned:
                continue
            cluster = [i_idx]
            assigned.add(i_idx)
            for j_idx in indices[i_pos + 1:]:
                if j_idx in assigned:
                    continue
                same_stride = (
                    threats[i_idx].get("stride_category", "")
                    == threats[j_idx].get("stride_category", "")
                    and threats[i_idx].get("stride_category", "")
                )
                threshold = _SAME_STRIDE_INTRA_THRESHOLD if same_stride else _DEDUP_SIMILARITY_THRESHOLD
                len_i = len(threats[i_idx].get("description") or "")
                len_j = len(threats[j_idx].get("description") or "")
                if len_i > 100 and len_j > 100:
                    ratio = min(len_i, len_j) / max(len_i, len_j)
                    if ratio < (1 - _LENGTH_DIFF_PENALTY_THRESHOLD):
                        threshold += 0.05
                sim = _weighted_jaccard(token_cache[i_idx], token_cache[j_idx])
                if sim >= threshold:
                    cluster.append(j_idx)
                    assigned.add(j_idx)
            local_clusters.append(cluster)

        for cluster in local_clusters:
            winner = _merge_cluster(threats, cluster)
            pass1_winners.append(winner)
            if len(cluster) > 1:
                merged_indices_p1.update(cluster[1:])

    if merged_indices_p1:
        logger.info(
            "[Dedup P1] Intra-component: %d -> %d (merged %d across %d groups)",
            len(threats), len(pass1_winners), len(merged_indices_p1), len(comp_groups),
        )

    # ── Pass 2: cross-component dedup (same STRIDE + high description similarity) ──
    stride_groups: dict[str, list[int]] = {}
    for i, t in enumerate(pass1_winners):
        cat = t.get("stride_category", "?")
        stride_groups.setdefault(cat, []).append(i)

    token_cache_p2 = {i: _tokenize(t.get("description", "")) for i, t in enumerate(pass1_winners)}
    absorbed: set[int] = set()
    pass2_winners: list[dict] = []

    for _cat, indices in stride_groups.items():
        if len(indices) <= 1:
            continue
        for i_pos, i_idx in enumerate(indices):
            if i_idx in absorbed:
                continue
            cluster = [i_idx]
            for j_idx in indices[i_pos + 1:]:
                if j_idx in absorbed:
                    continue
                sim = _weighted_jaccard(token_cache_p2[i_idx], token_cache_p2[j_idx])
                if sim >= _CROSS_GROUP_SIMILARITY_THRESHOLD:
                    cluster.append(j_idx)
                    absorbed.add(j_idx)
            if len(cluster) > 1:
                winner = _merge_cluster(pass1_winners, cluster)
                pass1_winners[i_idx] = winner
                absorbed.update(cluster[1:])

    pass2_winners = [t for i, t in enumerate(pass1_winners) if i not in absorbed]

    if absorbed:
        logger.info(
            "[Dedup P2] Cross-component: %d -> %d (merged %d with same STRIDE + similar desc)",
            len(pass1_winners), len(pass2_winners), len(absorbed),
        )

    total_merged = len(merged_indices_p1) + len(absorbed)
    if total_merged:
        logger.info(
            "[Dedup] Reduced %d threats to %d (merged %d duplicates across %d component groups)",
            len(threats), len(pass2_winners), total_merged, len(comp_groups),
        )
    return pass2_winners
