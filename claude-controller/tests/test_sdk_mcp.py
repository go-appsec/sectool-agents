"""Handler rejections must reach the model as errored tool results.

Exercises the installed SDK's control-bridge entry point
(`Query._handle_sdk_mcp_request`, the same method that serves tools/call in
production) against servers built by `build_worker_mcp_server`,
`build_orch_mcp_server`, and `build_bash_mcp_server`. Rejections must come
back as results carrying `isError: true` (which the CLI turns into errored
tool results for the model) while successes stay clean results.

Requires claude-agent-sdk >=0.2, whose bridge serves SDK MCP servers over a
real in-process MCP session; see requirements.txt.
"""

import asyncio
import unittest

from claude_agent_sdk._internal.query import Query

from bash_tool import build_bash_mcp_server
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
    """One tools/call through the real SDK control bridge.

    Runs the MCP initialize handshake first — SDK >=0.2 serves requests over
    a real in-process session and rejects calls before it — then returns the
    JSON-RPC response for the single call.
    """

    async def run():
        query = Query(
            _StubTransport(),
            is_streaming_mode=True,
            sdk_mcp_servers={server_name: server_config["instance"]},
        )
        try:
            await query._handle_sdk_mcp_request(server_name, {
                "jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "sectool-tests", "version": "0"},
                },
            })
            await query._handle_sdk_mcp_request(server_name, {
                "jsonrpc": "2.0", "method": "notifications/initialized",
            })
            return await query._handle_sdk_mcp_request(server_name, {
                "jsonrpc": "2.0", "id": 2, "method": "tools/call",
                "params": {"name": name, "arguments": arguments},
            })
        finally:
            # The bridge session and Query's internal anyio streams are only
            # torn down by the reader loop, which these one-shot dispatches
            # never start.
            for bridge in query._sdk_mcp_bridges.values():
                await bridge.aclose()
            query._message_send.close()
            query._message_receive.close()

    return asyncio.run(run())


def _rejection_text(resp) -> str:
    """Text blocks of an errored result, joined for assertions."""
    result = resp.get("result", {})
    return "\n".join(
        block["text"]
        for block in result.get("content", [])
        if isinstance(block, dict) and block.get("type") == "text"
    )


def assert_errored_result(test, resp):
    test.assertNotIn("error", resp)
    test.assertIsNotNone(resp.get("result"))
    test.assertIs(resp["result"].get("isError"), True)


class TestWorkerToolErrorPropagation(unittest.TestCase):
    def setUp(self):
        self.pool = CandidatePool()
        self.config = build_worker_mcp_server(self.pool, worker_id=1)

    def test_rejection_is_errored_result(self):
        """Handler is_error dicts must surface isError on the wire."""
        args = dict(_VALID_REPORT, summary="too short")
        resp = _call_tool(self.config, "worker_tools", "report_finding_candidate", args)
        assert_errored_result(self, resp)
        self.assertIn("Rejected: summary too short", _rejection_text(resp))
        # The rejection must not have recorded a candidate.
        self.assertEqual(len(self.pool.pending()), 0)

    def test_schema_violation_is_errored_result(self):
        args = {k: v for k, v in _VALID_REPORT.items() if k != "title"}
        resp = _call_tool(self.config, "worker_tools", "report_finding_candidate", args)
        assert_errored_result(self, resp)
        self.assertIn("Input validation error", _rejection_text(resp))

    def test_unknown_tool_is_errored_result(self):
        resp = _call_tool(self.config, "worker_tools", "no_such_tool", {})
        assert_errored_result(self, resp)

    def test_success_stays_clean_result(self):
        resp = _call_tool(
            self.config, "worker_tools", "report_finding_candidate", _VALID_REPORT)
        self.assertNotIn("error", resp)
        result = resp["result"]
        self.assertFalse(result.get("isError"))
        text = result["content"][0]["text"]
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

    def test_wrong_phase_rejection_is_errored_result(self):
        """Phase gating must reach the model as an errored result."""
        args = {
            "title": "t", "severity": "high", "endpoint": "/x",
            "description": "d", "reproduction_steps": "r", "evidence": "e",
            "impact": "i", "verification_notes": "v",
        }
        resp = _call_tool(self.config, "orch_tools", "file_finding", args)
        assert_errored_result(self, resp)
        message = _rejection_text(resp)
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

    def test_unresolved_pending_rejected_as_errored_result(self):
        decisions = self._verification_queue()
        config = self._config(decisions, ["c001"])
        resp = _call_tool(
            config, "orch_tools", "verification_done", {"summary": "done"})
        assert_errored_result(self, resp)
        message = _rejection_text(resp)
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
        result = resp["result"]
        self.assertFalse(result.get("isError"))
        text = result["content"][0]["text"]
        self.assertIn("Verification phase complete", text)
        self.assertIn("c001", text)
        self.assertEqual(decisions.verification_done_summary, "done")

    def test_resolved_pending_accepted_without_confirm(self):
        decisions = self._verification_queue()
        config = self._config(decisions, [])
        resp = _call_tool(
            config, "orch_tools", "verification_done", {"summary": "done"})
        self.assertNotIn("error", resp)
        result = resp["result"]
        self.assertFalse(result.get("isError"))
        self.assertEqual(result["content"][0]["text"], "Verification phase complete.")


class TestBashToolServer(unittest.TestCase):
    def test_rejection_is_errored_result(self):
        """bash_tool rejections ride the same isError channel."""
        config = build_bash_mcp_server()
        resp = _call_tool(config, "bash_tools", "bash", {"command": ""})
        assert_errored_result(self, resp)


if __name__ == "__main__":
    unittest.main()
