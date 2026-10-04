"""SDK MCP servers whose handler rejections reach the model as errors.

claude-agent-sdk 0.1.48 loses rejections twice between handler and CLI:
`create_sdk_mcp_server` flattens result dicts to their content list, and its
control bridge never translates `CallToolResult(isError=True)` into the
CLI's wire format, so every rejection lands as a successful tool result
(issue 26). The bundled CLI does surface JSON-RPC-level tool errors as
errored results, so this wrapper swaps in a tools/call dispatcher that
validates input against the advertised schema, runs the handler once, and
raises on `is_error` results. Remove once an SDK with both fixes is
required.
"""

from __future__ import annotations

from typing import Any

import jsonschema
from claude_agent_sdk import SdkMcpTool, create_sdk_mcp_server as _sdk_create_server
from claude_agent_sdk.types import McpSdkServerConfig
from mcp.types import (
    CallToolRequest,
    CallToolResult,
    ImageContent,
    ServerResult,
    TextContent,
)


class ToolRejectionError(Exception):
    """A tool call failed. Message text is surfaced to the calling model."""


def _rejection_text(result: dict[str, Any]) -> str:
    """Text blocks of a handler result, joined for the error response."""
    return "\n".join(
        block["text"]
        for block in result.get("content", [])
        if isinstance(block, dict) and block.get("type") == "text"
    )


def _dispatch_handler(tools_by_name: dict[str, SdkMcpTool[Any]]):
    """tools/call handler replacing the SDK's rejection-dropping one."""

    async def call_tool(req: CallToolRequest) -> ServerResult:
        name = req.params.name if req.params else None
        tool_def = tools_by_name.get(name or "")
        if tool_def is None:
            raise ToolRejectionError(f"Tool '{name}' not found")
        args = dict(req.params.arguments or {})
        try:
            jsonschema.validate(instance=args, schema=tool_def.input_schema)
        except jsonschema.ValidationError as e:
            raise ToolRejectionError(f"Input validation error: {e.message}")
        result = await tool_def.handler(args)
        if isinstance(result, dict) and result.get("is_error"):
            # isError results are dropped by this SDK's control bridge.
            # Raising instead routes the text through the JSON-RPC error
            # channel, which the CLI reports as an errored tool result.
            raise ToolRejectionError(_rejection_text(result))
        blocks: list[TextContent | ImageContent] = []
        for item in result.get("content", []):
            if item.get("type") == "text":
                blocks.append(TextContent(type="text", text=item["text"]))
            elif item.get("type") == "image":
                blocks.append(ImageContent(
                    type="image", data=item["data"], mimeType=item["mimeType"],
                ))
        return ServerResult(CallToolResult(content=blocks))

    return call_tool


def build_sdk_mcp_server(
    name: str,
    version: str = "1.0.0",
    tools: list[SdkMcpTool[Any]] | None = None,
) -> McpSdkServerConfig:
    """Like `claude_agent_sdk.create_sdk_mcp_server`, with visible rejections.

    Handlers keep the documented contract of returning
    `{"content": [...], "is_error": True}` dicts. This builder guarantees
    that the error flag survives dispatch to the CLI.
    """
    config = _sdk_create_server(name=name, version=version, tools=tools or [])
    by_name = {t.name: t for t in (tools or [])}
    config["instance"].request_handlers[CallToolRequest] = _dispatch_handler(by_name)
    return config
