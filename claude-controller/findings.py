"""Finding file writer.

Findings are written from the orchestrator's structured `file_finding` tool
call. The legacy text-based parser has been removed — the orchestrator
produces well-formed fields directly.
"""

import os
import re

from tools import FindingCandidate, FindingFiled


def slugify(text: str) -> str:
    text = text.lower().strip()
    text = re.sub(r"[^\w\s-]", "", text)
    text = re.sub(r"[-\s]+", "-", text)
    return text.strip("-")


def _canonical_endpoint(endpoint: str) -> str:
    """Normalize an endpoint string for dedup comparison."""
    if not endpoint:
        return ""
    # Strip method prefix if present
    parts = endpoint.strip().split(None, 1)
    path = parts[1] if len(parts) == 2 and parts[0].upper() in {
        "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS",
    } else endpoint
    path = path.strip().lower()
    # Drop query string and trailing slash
    path = path.split("?", 1)[0].rstrip("/")
    return path


def _titles_similar(a: str, b: str) -> bool:
    sa, sb = slugify(a), slugify(b)
    if not sa or not sb:
        return False
    if sa == sb or sa in sb or sb in sa:
        return True
    wa, wb = set(sa.split("-")), set(sb.split("-"))
    if not wa or not wb:
        return False
    overlap = len(wa & wb) / max(len(wa), len(wb))
    # 0.5 catches near-duplicate titles like
    #   "Wildcard CORS Enables Cross-Origin Token Status Enumeration and Response Leakage"
    # vs
    #   "Wildcard CORS Enables Cross-OAuth Response Leakage at Token and Introspection Endpoints"
    # (8/12 = 0.667). Used only by `match_pending_candidates` for auto-resolving
    # pending candidates when the verifier files without explicit
    # `supersedes_candidate_ids` — the safety net side; explicit dedup is the
    # verifier's call (see `merge_into_finding`).
    return overlap > 0.5


def match_pending_candidates(
    filed: FindingFiled, pending: list[FindingCandidate],
) -> list[str]:
    """Return candidate_ids from `pending` whose endpoint and title match `filed`.

    Used when the verifier files a finding without `supersedes_candidate_ids`
    so the controller can still mark the originating candidate(s) resolved.
    Ambiguous cases (e.g. endpoint-only hits) are deliberately NOT matched
    here — those candidates stay pending and the verifier must resolve them
    explicitly on the next substep.
    """
    filed_ep = _canonical_endpoint(filed.endpoint)
    if not filed_ep or not filed.title:
        return []
    matched: list[str] = []
    for c in pending:
        if _canonical_endpoint(c.endpoint) != filed_ep:
            continue
        if not _titles_similar(c.title, filed.title):
            continue
        matched.append(c.candidate_id)
    return matched


_MARKDOWN_TEMPLATE = """\
# {title}

- **Severity**: {severity}
- **Affected Endpoint**: {endpoint}

## Description

{description}

## Reproduction Steps

{reproduction_steps}

## Evidence

{evidence}

## Impact

{impact}

## Verification

{verification_notes}
"""


_UNVERIFIED_TEMPLATE = """\
# UNVERIFIED — {title}

> **WARNING:** This candidate was reported by a worker but the run was aborted
> before the verifier could reproduce it. Treat this as a lead, not a confirmed
> finding. The reported severity is the worker's claim, not a verified
> assessment.

- **Reported severity**: {severity}
- **Reported endpoint**: {endpoint}
- **Candidate ID**: {candidate_id}
- **Reporting worker**: {worker_id}
- **Flow IDs (worker session)**: {flow_ids}

## Worker summary

{summary}

## Worker evidence notes

{evidence_notes}

## Reproduction hint

{reproduction_hint}
"""


class FindingWriter:
    """Persists verified findings from `FindingFiled` records."""

    def __init__(self, findings_dir: str) -> None:
        self.findings_dir = findings_dir
        self.count = 0
        self.paths: list[str] = []
        self._index: list[dict] = []

    def summary_for_orchestrator(self) -> str:
        if not self._index:
            return "No findings filed yet."
        lines = []
        for entry in self._index:
            sev = entry["severity"] or "unknown"
            ep = entry["endpoint"] or "N/A"
            lines.append(f"{entry['finding_id']}. [{sev}] {entry['title']} — {ep}")
        return "**Findings filed so far:**\n" + "\n".join(lines)

    def summary_for_verifier(self, intro_chars: int = 240) -> str:
        """Verifier-facing roster: includes description excerpts and stable F-IDs.

        The verifier uses this to decide whether a new candidate is a true
        duplicate / extension of an existing finding (in which case it should
        call `merge_into_finding`) or a separate vulnerability that happens
        to share a name. The dedup call is the verifier's; this surface just
        gives it enough context to decide.
        """
        if not self._index:
            return "No findings filed yet."
        lines = ["**Findings filed so far (use `finding_id` to reference for merge):**"]
        for entry in self._index:
            sev = entry["severity"] or "unknown"
            ep = entry["endpoint"] or "N/A"
            extras = entry.get("extra_endpoints") or []
            if extras:
                ep = ep + " (+ merged: " + ", ".join(extras) + ")"
            intro = (entry.get("description") or "").strip()
            if len(intro) > intro_chars:
                intro = intro[: intro_chars - 1].rstrip() + "…"
            lines.append(
                f"- `{entry['finding_id']}` [{sev}] {entry['title']} — {ep}\n"
                f"  intro: {intro or '(no description)'}"
            )
            for note in entry.get("merge_notes") or []:
                if note:
                    lines.append(f"  merged: {note}")
        return "\n".join(lines)

    def get_by_finding_id(self, finding_id: str) -> dict | None:
        fid = (finding_id or "").strip()
        if not fid:
            return None
        for entry in self._index:
            if entry["finding_id"] == fid:
                return entry
        return None

    def summary_for_worker(self) -> str:
        """Worker-facing roster: title + endpoint only, no severity.

        Severity and verifier reasoning are intentionally omitted — workers
        might argue with the verifier's judgement rather than do new work.
        Returns an empty string when nothing has been filed so the caller
        can suppress the whole block.
        """
        if not self._index:
            return ""
        lines = []
        for entry in self._index:
            ep = entry["endpoint"] or "N/A"
            lines.append(f"- {entry['title']} — {ep}")
        return "Findings filed so far — do not re-file:\n" + "\n".join(lines)

    def write(self, filed: FindingFiled) -> str:
        os.makedirs(self.findings_dir, exist_ok=True)
        self.count += 1

        slug = slugify(filed.title) or "untitled"
        if len(slug) > 60:
            slug = slug[:60].rstrip("-")
        filename = f"finding-{self.count:02d}-{slug}.md"
        filepath = os.path.join(self.findings_dir, filename)

        body = _MARKDOWN_TEMPLATE.format(
            title=filed.title,
            severity=filed.severity,
            endpoint=filed.endpoint or "N/A",
            description=filed.description or "(none)",
            reproduction_steps=filed.reproduction_steps or "(none)",
            evidence=filed.evidence or "(none)",
            impact=filed.impact or "(none)",
            verification_notes=filed.verification_notes or "(none)",
        )
        with open(filepath, "w") as f:
            f.write(body)

        self.paths.append(filepath)
        self._index.append({
            "finding_id": f"F{self.count}",
            "title": filed.title,
            "title_slug": slugify(filed.title),
            "endpoint": _canonical_endpoint(filed.endpoint),
            "severity": filed.severity,
            "description": filed.description or "",
            "path": filepath,
        })
        return filepath

    def write_unverified_candidate(self, candidate: FindingCandidate) -> str:
        """Write a still-pending candidate as an UNVERIFIED finding file.

        Used when the run is aborted before verification could reproduce
        every candidate. The file is clearly marked so a reviewer doesn't
        mistake it for a confirmed finding.
        """
        os.makedirs(self.findings_dir, exist_ok=True)
        slug = slugify(candidate.title) or "untitled"
        if len(slug) > 60:
            slug = slug[:60].rstrip("-")
        filename = f"unverified-{candidate.candidate_id}-{slug}.md"
        filepath = os.path.join(self.findings_dir, filename)

        body = _UNVERIFIED_TEMPLATE.format(
            title=candidate.title or "(no title)",
            severity=candidate.severity or "unknown",
            endpoint=candidate.endpoint or "N/A",
            candidate_id=candidate.candidate_id,
            worker_id=candidate.worker_id if candidate.worker_id is not None else "(unknown)",
            flow_ids=", ".join(candidate.flow_ids) if candidate.flow_ids else "(none)",
            summary=candidate.summary or "(none)",
            evidence_notes=candidate.evidence_notes or "(none)",
            reproduction_hint=candidate.reproduction_hint or "(none)",
        )
        with open(filepath, "w") as f:
            f.write(body)

        self.paths.append(filepath)
        return filepath

    def merge(
        self,
        finding_id: str,
        *,
        rationale: str,
        additional_endpoint: str = "",
        additional_evidence: str = "",
        additional_reproduction_steps: str = "",
        additional_verification_notes: str = "",
        additional_impact: str = "",
    ) -> str | None:
        """Append a verifier-supplied addendum to an existing finding.

        The verifier calls this when a new candidate represents the same
        underlying vulnerability as a previously-filed finding (typically a
        new endpoint surface or new evidence). Returns the finding's path on
        success, None when `finding_id` doesn't resolve.
        """
        entry = self.get_by_finding_id(finding_id)
        if entry is None:
            return None

        sections: list[str] = []
        sections.append(f"\n\n## Merge addendum ({finding_id})\n")
        sections.append(f"**Rationale:** {rationale.strip() or '(none)'}")
        if additional_endpoint.strip():
            sections.append(f"\n**Additional endpoint:** {additional_endpoint.strip()}")
        if additional_evidence.strip():
            sections.append("\n### Additional evidence\n")
            sections.append(additional_evidence.strip())
        if additional_reproduction_steps.strip():
            sections.append("\n### Additional reproduction steps\n")
            sections.append(additional_reproduction_steps.strip())
        if additional_verification_notes.strip():
            sections.append("\n### Additional verification notes\n")
            sections.append(additional_verification_notes.strip())
        if additional_impact.strip():
            sections.append("\n### Impact addendum\n")
            sections.append(additional_impact.strip())

        with open(entry["path"], "a") as f:
            f.write("\n".join(sections) + "\n")

        # Reflect merged content in the verifier-facing roster so the next
        # substep's `summary_for_verifier` shows the additional endpoint and
        # merge rationale — otherwise a later candidate covering the merged
        # surface could look like a separate finding.
        extra_endpoints = entry.setdefault("extra_endpoints", [])
        if additional_endpoint.strip():
            ep_canon = _canonical_endpoint(additional_endpoint)
            if ep_canon and ep_canon not in extra_endpoints and ep_canon != entry["endpoint"]:
                extra_endpoints.append(ep_canon)
        merge_notes = entry.setdefault("merge_notes", [])
        merge_notes.append(rationale.strip())
        return entry["path"]
