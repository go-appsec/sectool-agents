"""Unit tests for FindingWriter with structured input."""

import os
import tempfile
import unittest

from findings import (
    FindingWriter,
    _canonical_endpoint,
    match_pending_candidates,
    slugify,
)
from tools import FindingCandidate, FindingFiled


def _make(title, endpoint="GET /x", severity="high"):
    return FindingFiled(
        title=title,
        severity=severity,
        endpoint=endpoint,
        description="d", reproduction_steps="rs",
        evidence="e", impact="i", verification_notes="v",
    )


class TestSlugify(unittest.TestCase):
    def test_basic(self):
        self.assertEqual(slugify("Reflected XSS in /search"), "reflected-xss-in-search")
        self.assertEqual(slugify("  Spaces  &  Symbols  !"), "spaces-symbols")
        self.assertEqual(slugify(""), "")


class TestCanonicalEndpoint(unittest.TestCase):
    def test_strip_method_and_normalize(self):
        self.assertEqual(_canonical_endpoint("GET /Search/"), "/search")
        self.assertEqual(_canonical_endpoint("POST /api/users?id=1"), "/api/users")
        self.assertEqual(_canonical_endpoint("/api/Users"), "/api/users")
        self.assertEqual(_canonical_endpoint(""), "")


class TestFindingWriter(unittest.TestCase):
    def test_write_structured_produces_markdown(self):
        with tempfile.TemporaryDirectory() as td:
            w = FindingWriter(td)
            path = w.write(_make("Reflected XSS in search"))
            self.assertEqual(os.path.basename(path), "finding-01-reflected-xss-in-search.md")
            body = open(path).read()
            self.assertIn("# Reflected XSS in search", body)
            self.assertIn("**Severity**: high", body)
            self.assertIn("## Verification", body)

    def test_summary_for_orchestrator(self):
        with tempfile.TemporaryDirectory() as td:
            w = FindingWriter(td)
            self.assertEqual(w.summary_for_orchestrator(), "No findings filed yet.")
            w.write(_make("XSS in X", endpoint="GET /x", severity="high"))
            w.write(_make("SQLi in Y", endpoint="POST /y", severity="critical"))
            out = w.summary_for_orchestrator()
            self.assertIn("F1. [high] XSS in X — /x", out)
            self.assertIn("F2. [critical] SQLi in Y — /y", out)

    def test_summary_for_verifier_includes_intro_and_id(self):
        with tempfile.TemporaryDirectory() as td:
            w = FindingWriter(td)
            self.assertEqual(w.summary_for_verifier(), "No findings filed yet.")
            filed = FindingFiled(
                title="Reflected XSS",
                severity="high",
                endpoint="GET /search",
                description="Search query is reflected unescaped into the response body.",
                reproduction_steps="rs", evidence="e", impact="i", verification_notes="v",
            )
            w.write(filed)
            out = w.summary_for_verifier()
            self.assertIn("`F1`", out)
            self.assertIn("Reflected XSS", out)
            self.assertIn("/search", out)
            self.assertIn("Search query is reflected", out)

    def test_merge_appends_addendum(self):
        with tempfile.TemporaryDirectory() as td:
            w = FindingWriter(td)
            path = w.write(_make("Reflected XSS", endpoint="GET /search"))
            merged = w.merge(
                "F1",
                rationale="Same vuln, additional endpoint",
                additional_endpoint="GET /lookup",
                additional_evidence="param `q` reflected on /lookup as well",
            )
            self.assertEqual(merged, path)
            body = open(path).read()
            self.assertIn("## Merge addendum (F1)", body)
            self.assertIn("Additional endpoint:** GET /lookup", body)
            self.assertIn("param `q` reflected", body)

    def test_merge_unknown_finding_id_returns_none(self):
        with tempfile.TemporaryDirectory() as td:
            w = FindingWriter(td)
            w.write(_make("Reflected XSS", endpoint="GET /search"))
            self.assertIsNone(w.merge("F99", rationale="r"))

    def test_merge_surfaces_in_verifier_summary(self):
        """After a merge, summary_for_verifier shows the merged endpoint and
        rationale so a later candidate covering that surface isn't mistaken
        for a separate finding."""
        with tempfile.TemporaryDirectory() as td:
            w = FindingWriter(td)
            w.write(_make("Reflected XSS", endpoint="GET /search"))
            w.merge(
                "F1",
                rationale="same vuln on /lookup too",
                additional_endpoint="GET /lookup",
            )
            out = w.summary_for_verifier()
            self.assertIn("/search", out)
            self.assertIn("merged: /lookup", out)
            self.assertIn("merged: same vuln on /lookup too", out)


def _candidate(cid: str, title: str, endpoint: str) -> FindingCandidate:
    return FindingCandidate(
        candidate_id=cid, worker_id=1, title=title, severity="high",
        endpoint=endpoint, flow_ids=["aaaa11"], summary="s",
        evidence_notes="e", reproduction_hint="r",
    )


class TestMatchPendingCandidates(unittest.TestCase):
    def test_matches_by_endpoint_and_title(self):
        filed = _make("Reflected XSS in search", endpoint="GET /search")
        pending = [_candidate("c001", "Reflected XSS in search results", "get /search/")]
        self.assertEqual(match_pending_candidates(filed, pending), ["c001"])

    def test_matches_near_duplicate_cors_titles(self):
        """0.5 similarity threshold must catch real near-duplicate titles.

        Two CORS write-ups for the same endpoint/issue with rearranged wording
        score 8/12 ≈ 0.667 word overlap. The previous 0.8 threshold missed
        these and left auto-resolve broken; 0.5 catches them.
        """
        filed = _make(
            "Wildcard CORS Enables Cross-Origin Token Status Enumeration and Response Leakage",
            endpoint="GET /oauth2/introspect",
        )
        pending = [_candidate(
            "c001",
            "Wildcard CORS Enables Cross-OAuth Response Leakage at Token and Introspection Endpoints",
            "GET /oauth2/introspect",
        )]
        self.assertEqual(match_pending_candidates(filed, pending), ["c001"])

    def test_requires_both_endpoint_and_title(self):
        filed = _make("Reflected XSS in search", endpoint="GET /search")
        pending = [
            _candidate("c001", "Reflected XSS in search", "POST /login"),  # title ok, endpoint wrong
            _candidate("c002", "SQL injection", "GET /search"),             # endpoint ok, title wrong
        ]
        self.assertEqual(match_pending_candidates(filed, pending), [])

    def test_returns_multiple_matches(self):
        filed = _make("Reflected XSS in search", endpoint="GET /search")
        pending = [
            _candidate("c001", "Reflected XSS in search", "GET /search"),
            _candidate("c002", "Reflected XSS in search results", "get /search/"),
        ]
        self.assertEqual(match_pending_candidates(filed, pending), ["c001", "c002"])

    def test_empty_endpoint_returns_empty(self):
        filed = _make("Reflected XSS", endpoint="")
        pending = [_candidate("c001", "Reflected XSS", "GET /search")]
        self.assertEqual(match_pending_candidates(filed, pending), [])


class TestFindingWriterSummaryForWorker(unittest.TestCase):
    """B2: summary_for_worker lists title+endpoint only, no severity."""

    def test_empty_returns_empty_string(self):
        with tempfile.TemporaryDirectory() as td:
            w = FindingWriter(td)
            self.assertEqual(w.summary_for_worker(), "")

    def test_populated_lists_title_and_endpoint_no_severity(self):
        with tempfile.TemporaryDirectory() as td:
            w = FindingWriter(td)
            w.write(_make("XSS in search", endpoint="GET /search", severity="high"))
            w.write(_make("SQLi in login", endpoint="POST /login", severity="critical"))
            out = w.summary_for_worker()
            self.assertIn("Findings filed so far — do not re-file:", out)
            self.assertIn("XSS in search — /search", out)
            self.assertIn("SQLi in login — /login", out)
            # Severity must NOT appear — workers might argue with verifier.
            self.assertNotIn("[high]", out)
            self.assertNotIn("[critical]", out)
            self.assertNotIn("critical", out)
            self.assertNotIn("high", out)


class TestWriteUnverifiedCandidate(unittest.TestCase):
    """write_unverified_candidate writes a clearly-marked UNVERIFIED file."""

    def _candidate(self) -> FindingCandidate:
        return FindingCandidate(
            candidate_id="c042",
            worker_id=3,
            title="Possible IDOR on /api/orgs/{id}",
            severity="high",
            endpoint="GET /api/orgs/123",
            flow_ids=["fl0w01", "fl0w02"],
            summary="GET on another org id returned 200 with member roster.",
            evidence_notes="Status 200, body included member emails.",
            reproduction_hint="Replay flow fl0w01 with id=124; expect 403.",
        )

    def test_writes_file_with_unverified_header(self):
        with tempfile.TemporaryDirectory() as td:
            fw = FindingWriter(td)
            path = fw.write_unverified_candidate(self._candidate())
            self.assertTrue(os.path.exists(path))
            with open(path) as f:
                body = f.read()
            self.assertIn("UNVERIFIED", body)
            self.assertIn("Possible IDOR on /api/orgs/{id}", body)
            self.assertIn("c042", body)
            self.assertIn("worker", body.lower())
            self.assertIn("fl0w01", body)
            self.assertIn("Replay flow fl0w01", body)
            # Filed-finding count must NOT advance — unverified is not a finding.
            self.assertEqual(fw.count, 0)

    def test_filename_includes_candidate_id(self):
        with tempfile.TemporaryDirectory() as td:
            fw = FindingWriter(td)
            path = fw.write_unverified_candidate(self._candidate())
            self.assertIn("unverified", os.path.basename(path))
            self.assertIn("c042", os.path.basename(path))

    def test_path_is_recorded_in_writer(self):
        with tempfile.TemporaryDirectory() as td:
            fw = FindingWriter(td)
            path = fw.write_unverified_candidate(self._candidate())
            self.assertIn(path, fw.paths)


if __name__ == "__main__":
    unittest.main()
