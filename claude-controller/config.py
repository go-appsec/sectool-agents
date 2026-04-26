"""Defaults and CLI argument parsing for the controller."""

import argparse
from dataclasses import dataclass

MODEL_MAP = {
    "sonnet": "claude-sonnet-4-5-20250929",
    "opus": "claude-opus-4-6",
    "haiku": "claude-haiku-4-5-20251001",
}


@dataclass
class Config:
    prompt: str
    proxy_port: int = 8181
    mcp_port: int = 9119
    findings_dir: str = "./findings"
    max_iterations: int = 30
    max_cost: float | None = None
    model: str = "sonnet"
    worker_model: str | None = None
    verbose: bool = False
    sectool_bin: str = "sectool"
    workflow: str = "explore"
    max_workers: int = 4

    @property
    def orchestrator_model_id(self) -> str:
        return MODEL_MAP.get(self.model, self.model)

    @property
    def worker_model_id(self) -> str | None:
        if self.worker_model is None:
            return None
        return MODEL_MAP.get(self.worker_model, self.worker_model)


def parse_args() -> Config:
    parser = argparse.ArgumentParser(
        description="Autonomous security exploration controller using Claude Agent SDK",
    )
    parser.add_argument(
        "--prompt", required=True, help="Initial task prompt for the worker",
    )
    parser.add_argument(
        "--proxy-port", type=int, default=8181,
        help="Port for sectool's native proxy (default: 8181)",
    )
    parser.add_argument(
        "--mcp-port", type=int, default=9119,
        help="Port for sectool's MCP server (default: 9119)",
    )
    parser.add_argument(
        "--findings-dir", default="./findings",
        help="Directory for finding report files (default: ./findings)",
    )
    parser.add_argument(
        "--max-iterations", type=int, default=30,
        help="Hard cap on orchestrator loop iterations (default: 30)",
    )
    parser.add_argument(
        "--max-cost", type=float, default=None,
        help="USD cost ceiling; halts loop if exceeded",
    )
    parser.add_argument(
        "--model", default="sonnet",
        help="Model alias for the orchestrator: sonnet, opus, haiku (default: sonnet)",
    )
    parser.add_argument(
        "--worker-model", default=None,
        help="Override model for the Claude Code worker",
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Print full worker and orchestrator outputs",
    )
    parser.add_argument(
        "--sectool-bin", default="sectool",
        help="Path to the sectool binary (default: 'sectool' on PATH)",
    )
    parser.add_argument(
        "--workflow", default="explore",
        help="Sectool workflow mode (default: explore)",
    )
    parser.add_argument(
        "--max-workers", type=int, default=4,
        help="Maximum parallel workers the orchestrator can assign (default: 4)",
    )
    args = parser.parse_args()
    max_workers = max(1, min(5, args.max_workers))
    return Config(
        prompt=args.prompt,
        proxy_port=args.proxy_port,
        mcp_port=args.mcp_port,
        findings_dir=args.findings_dir,
        max_iterations=args.max_iterations,
        max_cost=args.max_cost,
        model=args.model,
        worker_model=args.worker_model,
        verbose=args.verbose,
        sectool_bin=args.sectool_bin,
        workflow=args.workflow,
        max_workers=max_workers,
    )
