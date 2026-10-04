"""Unit tests for FindingWriter with structured input."""

import os
import tempfile
import unittest

from findings import (
    FindingWriter,
    _canonical_endpoint,
    finding_dedup_key,
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

    def test_underscore_equals_hyphen(self):
        # Mirrors secagent's TestSlugify: underscored and hyphenated titles
        # must produce the same slug.
        self.assertEqual(slugify("plaintext client_secret exposure"), "plaintext-client-secret-exposure")
        self.assertEqual(slugify("plaintext client-secret exposure"), "plaintext-client-secret-exposure")


class TestCanonicalEndpoint(unittest.TestCase):
    def test_strip_method_and_normalize(self):
        self.assertEqual(_canonical_endpoint("GET /Search/"), "/search")
        self.assertEqual(_canonical_endpoint("POST /api/users?id=1"), "/api/users")
        self.assertEqual(_canonical_endpoint("/api/Users"), "/api/users")
        self.assertEqual(_canonical_endpoint(""), "")

    def test_root_path_distinct_from_missing(self):
        self.assertEqual(_canonical_endpoint("/"), "/")
        self.assertEqual(_canonical_endpoint("///"), "/")
        self.assertEqual(_canonical_endpoint("GET /"), "/")
        self.assertEqual(_canonical_endpoint("GET /?q=1"), "/")

    def test_numeric_segments_rewrite_to_id(self):
        self.assertEqual(_canonical_endpoint("GET /users/123"), "/users/:id")
        self.assertEqual(_canonical_endpoint("/Users/42"), "/users/:id")
        self.assertEqual(
            _canonical_endpoint("/api/orgs/123/v2/items/9"),
            "/api/orgs/:id/v2/items/:id",
        )

    def test_non_numeric_segments_stay_literal(self):
        # Mirrors Go's ParseUint: names, signs, and template segments
        # never rewrite.
        self.assertEqual(_canonical_endpoint("/users/alice"), "/users/alice")
        self.assertEqual(_canonical_endpoint("/files/-1"), "/files/-1")
        self.assertEqual(_canonical_endpoint("/api/orgs/{id}"), "/api/orgs/{id}")

    def test_numeric_rewrite_uint64_bound(self):
        # Boundary parity with Go's strconv.ParseUint overflow rejection.
        self.assertEqual(
            _canonical_endpoint("/n/18446744073709551615"), "/n/:id")
        self.assertEqual(
            _canonical_endpoint("/n/99999999999999999999"),
            "/n/99999999999999999999",
        )


class TestFindingWriter(unittest.TestCase):
    def test_write_structured_produces_markdown(self):
        with tempfile.TemporaryDirectory() as td:
            w = FindingWriter(td)
            path = w.write(_make("Reflected XSS in search"))
            self.assertEqual(os.path.basename(path), "finding-01-reflected-xss-in-search.md")
            with open(path) as f:
                body = f.read()
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
            )
            self.assertEqual(merged, path)
            with open(path) as f:
                body = f.read()
            self.assertIn("## Additional affected surfaces", body)
            self.assertIn("- GET /lookup — Same vuln, additional endpoint", body)

    def test_merge_repeated_appends_to_single_section(self):
        with tempfile.TemporaryDirectory() as td:
            w = FindingWriter(td)
            path = w.write(_make("Reflected XSS", endpoint="GET /search"))
            w.merge("F1", rationale="endpoint two", additional_endpoint="GET /lookup")
            w.merge("F1", rationale="endpoint three", additional_endpoint="POST /search-v2")
            with open(path) as f:
                body = f.read()
            # Single section heading, both bullets present.
            self.assertEqual(body.count("## Additional affected surfaces"), 1)
            self.assertIn("- GET /lookup — endpoint two", body)
            self.assertIn("- POST /search-v2 — endpoint three", body)

    def test_merge_without_endpoint_records_rationale(self):
        with tempfile.TemporaryDirectory() as td:
            w = FindingWriter(td)
            path = w.write(_make("Reflected XSS", endpoint="GET /search"))
            w.merge("F1", rationale="stronger evidence on the same surface")
            with open(path) as f:
                body = f.read()
            self.assertIn("- _(same surface)_ — stronger evidence on the same surface", body)

    def test_merge_with_evidence_note_renders_sub_bullet(self):
        with tempfile.TemporaryDirectory() as td:
            w = FindingWriter(td)
            path = w.write(_make("Reflected XSS", endpoint="GET /search"))
            w.merge(
                "F1",
                rationale="same surface, stronger payload",
                evidence_note="payload bypassed CSP via SVG",
            )
            with open(path) as f:
                body = f.read()
            self.assertIn("- _(same surface)_ — same surface, stronger payload", body)
            self.assertIn("  - payload bypassed CSP via SVG", body)

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


class TestFindingDedupKey(unittest.TestCase):
    def test_same_title_different_endpoints_differ(self):
        """Issue 19: same-titled findings on distinct endpoints must both write."""
        a = finding_dedup_key(_make("SQL injection", endpoint="GET /search"))
        b = finding_dedup_key(_make("SQL injection", endpoint="POST /login"))
        self.assertNotEqual(a, b)

    def test_same_title_same_endpoint_collide(self):
        # Case, method casing, trailing slash, and query strings normalize away.
        a = finding_dedup_key(_make("SQL injection", endpoint="GET /search"))
        b = finding_dedup_key(_make("sql INJECTION", endpoint="get /Search/?q=1"))
        self.assertEqual(a, b)

    def test_numeric_endpoint_ids_collide(self):
        a = finding_dedup_key(_make("IDOR on org roster", endpoint="GET /api/orgs/123"))
        b = finding_dedup_key(_make("IDOR on org roster", endpoint="/api/orgs/456"))
        self.assertEqual(a, b)

    def test_title_punctuation_normalizes(self):
        # Slug parity: hyphen/underscore/case variants are the same title.
        a = finding_dedup_key(_make("plaintext client-secret exposure", endpoint="GET /x"))
        b = finding_dedup_key(_make("Plaintext Client_Secret Exposure", endpoint="GET /x"))
        self.assertEqual(a, b)

    def test_unsluggable_title_falls_back_to_raw(self):
        a = finding_dedup_key(_make("!!!", endpoint="GET /x"))
        b = finding_dedup_key(_make("???", endpoint="GET /x"))
        self.assertNotEqual(a, b)

    def test_empty_endpoint_keys_distinct_from_root(self):
        a = finding_dedup_key(_make("XSS", endpoint=""))
        b = finding_dedup_key(_make("XSS", endpoint="/"))
        self.assertNotEqual(a, b)


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

    def test_underscore_title_matches_hyphen(self):
        filed = _make("plaintext client-secret exposure", endpoint="GET /search")
        pending = [_candidate("c001", "plaintext client_secret exposure", "GET /search")]
        self.assertEqual(match_pending_candidates(filed, pending), ["c001"])

    def test_empty_endpoint_returns_empty(self):
        filed = _make("Reflected XSS", endpoint="")
        pending = [_candidate("c001", "Reflected XSS", "GET /search")]
        self.assertEqual(match_pending_candidates(filed, pending), [])

    def test_root_endpoint_matches_root(self):
        filed = _make("Reflected XSS", endpoint="GET /")
        pending = [_candidate("c001", "Reflected XSS in root", "///")]
        self.assertEqual(match_pending_candidates(filed, pending), ["c001"])

    def test_different_ids_still_match(self):
        """The issue-18 failure mode: concrete IDs on the same route must
        not block candidate auto-resolution."""
        filed = _make("IDOR on org roster", endpoint="GET /api/orgs/456")
        pending = [_candidate("c001", "IDOR on org roster", "get /api/orgs/123")]
        self.assertEqual(match_pending_candidates(filed, pending), ["c001"])

    def test_root_endpoint_never_matches_missing(self):
        filed = _make("Reflected XSS", endpoint="")
        pending = [_candidate("c001", "SQL Injection", "/")]
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


class TestFindingWriterResume(unittest.TestCase):
    """Reruns into an existing dir continue numbering without truncating."""

    def _seed(self, td: str, name: str, body: str = "prior\n") -> None:
        with open(os.path.join(td, name), "w") as f:
            f.write(body)

    def test_count_seeded_from_disk(self):
        with tempfile.TemporaryDirectory() as td:
            self._seed(td, "finding-01-x.md")
            self._seed(td, "finding-03-y.md")
            w = FindingWriter(td)
            self.assertEqual(w.count, 3)

    def test_rerun_continues_numbering(self):
        with tempfile.TemporaryDirectory() as td:
            self._seed(td, "finding-01-reflected-xss.md", "# prior\n")
            w = FindingWriter(td)
            path = w.write(_make("Reflected XSS"))
            self.assertEqual(os.path.basename(path), "finding-02-reflected-xss.md")
            with open(os.path.join(td, "finding-01-reflected-xss.md")) as f:
                self.assertEqual(f.read(), "# prior\n")

    def test_write_bumps_past_new_collision(self):
        """Files created after construction must not be truncated either."""
        with tempfile.TemporaryDirectory() as td:
            w = FindingWriter(td)
            self._seed(td, "finding-01-same-slug.md")
            path = w.write(_make("Same Slug"))
            self.assertEqual(os.path.basename(path), "finding-02-same-slug.md")
            with open(os.path.join(td, "finding-01-same-slug.md")) as f:
                self.assertEqual(f.read(), "prior\n")

    def test_run_count_tracks_this_run_only(self):
        with tempfile.TemporaryDirectory() as td:
            self._seed(td, "finding-05-prior.md")
            w = FindingWriter(td)
            w.write(_make("New finding"))
            self.assertEqual(w.count, 6)
            self.assertEqual(w.run_count, 1)
            self.assertIn("F6. [high] New finding", w.summary_for_orchestrator())

    def test_unverified_rerun_continues_numbering(self):
        with tempfile.TemporaryDirectory() as td:
            self._seed(td, "unverified-01-old.md", "# prior\n")
            w = FindingWriter(td)
            path = w.write_unverified_candidate(_candidate("c001", "Old dump", "/x"))
            self.assertEqual(os.path.basename(path), "unverified-02-old-dump.md")
            with open(os.path.join(td, "unverified-01-old.md")) as f:
                self.assertEqual(f.read(), "# prior\n")

    def test_unverified_bumps_past_new_collision(self):
        with tempfile.TemporaryDirectory() as td:
            w = FindingWriter(td)
            self._seed(td, "unverified-01-old-dump.md")
            path = w.write_unverified_candidate(_candidate("c001", "Old dump", "/x"))
            self.assertEqual(os.path.basename(path), "unverified-02-old-dump.md")


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
            # Unverified writes never advance the filed-finding counter.
            self.assertEqual(fw.run_count, 0)

    def test_sequential_filenames(self):
        with tempfile.TemporaryDirectory() as td:
            fw = FindingWriter(td)
            path1 = fw.write_unverified_candidate(self._candidate())
            path2 = fw.write_unverified_candidate(self._candidate())
            self.assertEqual(os.path.basename(path1),
                             "unverified-01-possible-idor-on-apiorgsid.md")
            self.assertEqual(os.path.basename(path2),
                             "unverified-02-possible-idor-on-apiorgsid.md")


class TestFindingWriterUtf8(unittest.TestCase):
    """Evidence files are UTF-8 regardless of ambient locale."""

    def _read_bytes(self, path: str) -> bytes:
        with open(path, "rb") as f:
            return f.read()

    def test_write_encodes_non_ascii_content(self):
        with tempfile.TemporaryDirectory() as td:
            w = FindingWriter(td)
            path = w.write(_make("Header injection — CRLF évidence"))
            self.assertIn("—".encode("utf-8"), self._read_bytes(path))

    def test_unverified_template_encodes_em_dash(self):
        # The template's own em dash must encode under a non-UTF-8 locale.
        with tempfile.TemporaryDirectory() as td:
            w = FindingWriter(td)
            path = w.write_unverified_candidate(
                _candidate("c001", "Old dump — évidence", "/x"))
            self.assertIn("—".encode("utf-8"), self._read_bytes(path))

    def test_merge_appends_utf8(self):
        with tempfile.TemporaryDirectory() as td:
            w = FindingWriter(td)
            w.write(_make("XSS"))
            path = w.merge("F1", rationale="évidence — same surface")
            self.assertIn(
                "évidence — same surface".encode("utf-8"),
                self._read_bytes(path),
            )


if __name__ == "__main__":
    unittest.main()
