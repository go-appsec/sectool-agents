"""Issue 26: handler rejections must survive real SDK dispatch.

Exercises the installed SDK's control-bridge entry point
(`Query._handle_sdk_mcp_request`, the same method that serves tools/call in
production) against servers built by `build_worker_mcp_server` and
`build_orch_mcp_server`. Rejections must come back as JSON-RPC error
responses (which the CLI turns into errored tool results) while successes
stay ordinary result responses.
"""

import asyncio
import unittest
import warnings

from claude_agent_sdk._internal.query import Query

from tools import (
    CandidatePool,
    DecisionQueue,
    PHASE_VERIFICATION,
    build_orch_mcp_server,
    build_worker_mcp_server,
)


_VALID_REPORT = {
    "title": "SQL injection in login",
    "severity": "high",
    "endpoint": "/api/login",
    "flow_ids": ["aaaa11"],
    "summary": "Union-based SQL injection in the login email parameter.",
    "evidence_notes": "Replay returned the full user table password hashes.",
    "reproduction_hint": "Replay flow aaaa11 with email=' union select — expect hash dump.",
}


class _StubTransport:
    async def read_messages(self):
        yield {}
        return

    async def write(self, data):
        pass

    async def close(self):
        pass

    async def end_input(self):
        pass


def _call_tool(server_config, server_name, name, arguments):
    """One tools/call through the real SDK control bridge."""
    query = Query(
        _StubTransport(),
        is_streaming_mode=True,
        sdk_mcp_servers={server_name: server_config["instance"]},
    )
    message = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments},
    }
    with warnings.catch_warnings():
        # Query's internal anyio streams are only closed by its reader loop,
        # which these one-shot dispatches never start.
        warnings.simplefilter("ignore", ResourceWarning)
        return asyncio.run(query._handle_sdk_mcp_request(server_name, message))


class TestWorkerToolErrorPropagation(unittest.TestCase):
    def setUp(self):
        self.pool = CandidatePool()
        self.config = build_worker_mcp_server(self.pool, worker_id=1)

    def test_rejection_is_errored_response(self):
        """Handler is_error dicts must not flatten into success results."""
        args = dict(_VALID_REPORT, summary="too short")
        resp = _call_tool(self.config, "worker_tools", "report_finding_candidate", args)
        self.assertIn("error", resp)
        self.assertNotIn("result", resp)
        self.assertIn("Rejected: summary too short", resp["error"]["message"])

    def test_schema_violation_is_errored_response(self):
        args = {k: v for k, v in _VALID_REPORT.items() if k != "title"}
        resp = _call_tool(self.config, "worker_tools", "report_finding_candidate", args)
        self.assertIn("error", resp)
        self.assertIn("Input validation error", resp["error"]["message"])

    def test_unknown_tool_is_errored_response(self):
        resp = _call_tool(self.config, "worker_tools", "no_such_tool", {})
        self.assertIn("error", resp)

    def test_success_stays_result_response(self):
        resp = _call_tool(
            self.config, "worker_tools", "report_finding_candidate", _VALID_REPORT)
        self.assertNotIn("error", resp)
        text = resp["result"]["content"][0]["text"]
        self.assertIn("Candidate c001 recorded", text)
        self.assertIsNotNone(self.pool.get("c001"))


class _IdleDecisions:
    """Minimal DecisionQueue stand-in pinned to the idle phase."""

    def __init__(self):
        self.phase = "idle"

    @property
    def current_phase(self):
        return self.phase


class TestOrchToolErrorPropagation(unittest.TestCase):
    def setUp(self):
        self.config = build_orch_mcp_server(
            _IdleDecisions(),
            alive_worker_ids=lambda: [],
            run_progress=lambda: (1, 0),
        )

    def test_wrong_phase_rejection_is_errored_response(self):
        """Phase gating must reach the model as an errored result."""
        args = {
            "title": "t", "severity": "high", "endpoint": "/x",
            "description": "d", "reproduction_steps": "r", "evidence": "e",
            "impact": "i", "verification_notes": "v",
        }
        resp = _call_tool(self.config, "orch_tools", "file_finding", args)
        self.assertIn("error", resp)
        self.assertNotIn("result", resp)
        message = resp["error"]["message"]
        self.assertIn("not allowed in phase 'idle'", message)
        self.assertIn("Expected phase 'verification'", message)


class TestVerificationDonePendingGuard(unittest.TestCase):
    """Issue 28: verification_done with unresolved pending candidates is
    rejected through the real dispatch path unless confirm_open is set."""

    def _config(self, decisions: DecisionQueue, pending: list[str]):
        return build_orch_mcp_server(
            decisions,
            pending_candidate_ids=lambda: pending,
        )

    def _verification_queue(self) -> DecisionQueue:
        q = DecisionQueue()
        q.begin_phase(PHASE_VERIFICATION)
        return q

    def test_unresolved_pending_rejected_as_errored_response(self):
        decisions = self._verification_queue()
        config = self._config(decisions, ["c001"])
        resp = _call_tool(
            config, "orch_tools", "verification_done", {"summary": "done"})
        self.assertIn("error", resp)
        message = resp["error"]["message"]
        self.assertIn("1 pending candidate(s) unresolved: c001", message)
        self.assertIn("confirm_open=true", message)
        # The guard must not have ended the phase.
        self.assertIsNone(decisions.verification_done_summary)

    def test_confirm_open_accepted_and_acknowledges(self):
        decisions = self._verification_queue()
        config = self._config(decisions, ["c001"])
        resp = _call_tool(
            config, "orch_tools", "verification_done",
            {"summary": "done", "confirm_open": True})
        self.assertNotIn("error", resp)
        text = resp["result"]["content"][0]["text"]
        self.assertIn("Verification phase complete", text)
        self.assertIn("c001", text)
        self.assertEqual(decisions.verification_done_summary, "done")

    def test_resolved_pending_accepted_without_confirm(self):
        decisions = self._verification_queue()
        config = self._config(decisions, [])
        resp = _call_tool(
            config, "orch_tools", "verification_done", {"summary": "done"})
        self.assertNotIn("error", resp)
        text = resp["result"]["content"][0]["text"]
        self.assertEqual(text, "Verification phase complete.")


if __name__ == "__main__":
    unittest.main()
