# go-appsec/sectool-agents

[![license](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/go-appsec/toolbox/blob/main/LICENSE)
[![Tests - Main Push](https://github.com/go-appsec/sectool-agents/actions/workflows/tests-main.yml/badge.svg)](https://github.com/go-appsec/sectool-agents/actions/workflows/tests-main.yml)

Agents that drive [`sectool`](https://github.com/go-appsec/toolbox) in autonomous security workflows. Each agent runs a multi-agent loop (workers + verifier + director) on top of sectool's MCP server so an LLM can autonomously explore a target for vulnerabilities, reproduce candidates, and file findings.

This repo is a home for multiple agent implementations. They all share the same agent contract (worker reports candidates, verifier reproduces and files, director plans the next iteration) — what differs is which SDK / model backend the agent runs on and which language it's written in.

These agents are not a substitute for a skilled tester. If you are already proficient, using Claude Code interactively with the sectool MCP is faster and cheaper. Use the autonomous agents to broaden coverage and probe additional areas in parallel with your own testing.

## Prerequisites

Every agent in this repo drives the `sectool` MCP API, which lives in the [go-appsec/toolbox](https://github.com/go-appsec/toolbox) repo and must be installed independently:

```bash
go install github.com/go-appsec/toolbox/sectool@latest
```

This places the `sectool` binary on your `GOBIN` (typically `$GOPATH/bin` or `~/go/bin`). Make sure that directory is on your `PATH`, or pass the binary path to the agent via its own flag — see each agent's README.

See the individual agent READMEs for any additional language / runtime prerequisites.

## Available agents

| Agent | Language | Backend | Auth |
|-------|----------|---------|------|
| [`claude-controller/`](claude-controller/) | Python | Claude Agent SDK | Claude Code OAuth (uses your `claude` CLI session) |

### [`claude-controller/`](claude-controller/)

[![Vibe-Scale 4.0(V2|U2|T1): Vibed code with gaps](https://img.shields.io/badge/Vibe--Scale%204.0(V2%7CU2%7CT1)-Vibed%20code%20with%20gaps-ff7f0e)](https://github.com/vibesdk/vibe-scale/blob/main/README.md)

A Python controller built on the Claude Agent SDK. Workers run as Claude Code instances connected to sectool's MCP server; the verifier and director are separate Claude instances with phase-gated tool surfaces and their own system prompts.

Use `claude-controller` if:

- You prefer Anthropic models and want to bill autonomous exploration to your existing Claude subscription, with no separate API key required.
- You want autonomous parallel probing: the director fans workers out across attack surface each iteration and can assign multiple workers to a promising area.
- You want to expand coverage alongside manual testing, running the agent in the background while you focus elsewhere.

See [`claude-controller/README.md`](claude-controller/README.md) for installation, flag reference, phase mechanics, and test instructions.

## Shared architecture

- **Workers** call sectool MCP tools (proxy, replay, crawl, OAST, diff/reflection, encoders) plus a `report_finding_candidate` tool.
- **Verifier** is a separate agent with the full sectool tool surface whose only job is to independently reproduce candidates, then call `file_finding` or `dismiss_candidate`.
- **Director** is a separate agent whose only job is to decide what each worker does next: `continue_worker`, `expand_worker`, `stop_worker`, `plan_workers`, or `done`. It also sets each worker's per-iteration `autonomous_budget`.
- The outer loop runs **autonomous worker turns → verification → direction** per iteration, with phase-gated tools so each role stays in lane.
- Findings are deduplicated and written as markdown files with a Verification section in the configured findings directory.

## Where findings land

Every agent writes to its `--findings-dir` (default `./findings/`) as `finding-NN-<slug>.md` files containing Title, Severity, Affected Endpoint, Description, Reproduction Steps, Evidence, Impact, and a Verification section sourced from the verifier's reproduction notes.

