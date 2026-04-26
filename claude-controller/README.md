# claude-controller - sectool agent on the Claude Agent SDK

[![Vibe-Scale 4.0(V2|U2|T1): Vibed code with gaps](https://img.shields.io/badge/Vibe--Scale%204.0(V2%7CU2%7CT1)-Vibed%20code%20with%20gaps-ff7f0e)](https://github.com/vibesdk/vibe-scale/blob/main/README.md)

Autonomous security exploration controller that runs multiple Claude instances with different responsibilities:

- **Worker(s)** — Claude Code connected to sectool's MCP server and a small in-process `worker_tools` MCP server. Workers execute security tests with sectool (proxy, replay, crawl, OAST, analysis tools) and, when they find something suspicious, call `report_finding_candidate(...)` to flag it.
- **Verifier** — dedicated Claude instance whose only job is to reproduce worker-reported candidates using the full sectool tool surface (`flow_get`, `replay_send`, `request_send`, `diff_flow`, `find_reflected`, `proxy_rule_*`, `crawl_*`, `oast_*`, …) and either `file_finding` or `dismiss_candidate`. Runs over multiple substeps per iteration so it can reflect between reproductions.
- **Director** — dedicated Claude instance whose only job is to decide what each alive worker should do next (`continue_worker`, `expand_worker`, `stop_worker`, `plan_workers`, `done`) and how long it may run autonomously before escalating back (`autonomous_budget`). Also runs over multiple substeps per iteration.

Splitting verification and direction into separate clients with separate system prompts forces each role to do its job thoroughly — the single-turn orchestrator of earlier versions tended to short-circuit both.

All instances authenticate via Claude Code's built-in OAuth — no API key required.

## Prerequisites

- Python 3.10+
- Claude Code CLI installed and authenticated (`claude` must be on `PATH`)
- `sectool` binary installed and available on `PATH` (or a path you'll pass via `--sectool-bin`). `sectool` is maintained in [go-appsec/toolbox](https://github.com/go-appsec/toolbox) and is not built by this project. Install it with:

  ```bash
  go install github.com/go-appsec/toolbox/sectool@latest
  ```

## Installation

```bash
cd claude-controller
pip install -r requirements.txt
```

## Usage

```bash
python controller.py \
  --prompt "The proxy is configured on port 8181. Explore https://target.example.com for security issues." \
  --proxy-port 8181 \
  --max-iterations 30 \
  --model sonnet \
  --verbose
```

If `sectool` is not on your `PATH`, point the controller at it explicitly:

```bash
python controller.py \
  --sectool-bin /path/to/sectool \
  --prompt "…"
```

## CLI Arguments

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `--prompt` | yes | — | Initial task prompt for the worker |
| `--proxy-port` | no | `8181` | Port for sectool's native proxy |
| `--mcp-port` | no | `9119` | Port for sectool's MCP server |
| `--findings-dir` | no | `./findings` | Directory for finding report files |
| `--max-iterations` | no | `30` | Hard cap on orchestrator loop iterations |
| `--max-cost` | no | none | USD cost ceiling; halts loop if exceeded |
| `--model` | no | `sonnet` | Model for the orchestrator (sonnet, opus, haiku) |
| `--worker-model` | no | none | Override model for the Claude Code worker |
| `--max-workers` | no | `4` | Maximum parallel workers the orchestrator can assign |
| `--verbose` | no | false | Print full worker and orchestrator outputs |
| `--sectool-bin` | no | `sectool` | Path to the sectool binary (default: looked up on `PATH`) |
| `--workflow` | no | `explore` | Sectool workflow mode |

## Using with an Existing MCP Server

If an MCP server is already accepting requests on `--mcp-port`, the controller detects it and reuses it instead of starting its own (and skips teardown of the externally-managed process).

```bash
# Start the MCP server separately
sectool mcp --proxy-port 8181 --workflow=explore

# In another terminal, run the controller — the existing server is auto-detected
python controller.py \
  --prompt "Explore https://target.example.com for auth vulnerabilities." \
  --proxy-port 8181 \
  --mcp-port 9119
```

## How It Works

1. **Launch MCP** — probes `--mcp-port`; if a server is already accepting requests, reuses it (and won't tear it down on exit). Otherwise starts `sectool mcp` as a subprocess on `--mcp-port` using the binary from `--sectool-bin` (or `PATH`). The controller does not build sectool; it must already be installed.
2. **Connect worker 1, verifier, and director** — all three share the sectool MCP server; the workers get an in-process `worker_tools` MCP server (exposing `report_finding_candidate`), and the verifier and director each connect to the shared in-process `orch_tools` MCP server (tools are phase-gated — see below). The verifier gets the full sectool tool surface; the director gets only worker-control tools.
3. **Initial prompt** — the user's prompt is sent to worker 1 for discovery.
4. **Per-iteration anatomy** (three phases):

   **Phase 1: Autonomous worker run.** Each alive worker runs concurrently for up to its `autonomous_budget` turns (default 8). Between turns, the controller sends a generic `"Continue your current testing plan."` prompt — no orchestrator intervention. A worker **escalates back** early if it reports a finding candidate, produces a silent turn (no tool calls, no new flow IDs), or hits a connection error. Each turn's summary (tool calls, flow IDs touched, candidates raised) is recorded on the worker. Controller waits until every worker has escalated.

   **Phase 2: Verification (multi-substep).** The verifier client receives the list of pending candidates + every worker's full autonomous-run transcript, and reproduces each candidate using sectool tools. It may take up to `VERIFICATION_MAX_SUBSTEPS` (6) query/drain substeps — between substeps the controller applies any `file_finding` / `dismiss_candidate` decisions and prompts again with the updated pending list. Phase ends on `verification_done(summary)`, when no pending candidates remain, or at the cap.

   **Phase 3: Direction (multi-substep).** The director client receives the verification summary + every worker's autonomous-run transcript, and issues `continue_worker` / `expand_worker` / `stop_worker` / `plan_workers` decisions — each with an `autonomous_budget` for the next iteration. Up to `DIRECTION_MAX_SUBSTEPS` (4) substeps followed by one mandatory **self-review** substep prompting the director to check for uncovered or misassigned workers before closing the phase. Phase ends on `direction_done(summary)`, on `done(summary)` to end the run, when every alive worker has a decision, or at the cap.

   A `done(summary)` called before iteration `MIN_ITERATIONS_FOR_DONE` (5) with zero findings filed is rejected as premature — this guards against models that confuse `done` with `direction_done` on early iterations.

   **Apply.** Controller applies the plan diff (spawn/retarget), sends each worker its instruction + updated budget, and starts the next iteration.

5. **Phase gating.** Each orch tool checks `decisions.phase` and rejects calls made in the wrong phase. Verification phase may call `file_finding`, `dismiss_candidate`, and `verification_done` (plus sectool read/replay tools). Direction phase may call `plan_workers`, `continue_worker`, `expand_worker`, `stop_worker`, `direction_done`, and `done`.
6. **Stall detection** — controller-observed via each worker's `escalation_reason`. `silent` escalations increment `progress_none_streak`; `candidate` escalations or turns that touched new flow IDs reset it. Three consecutive silent escalations triggers a stall warning in the director prompt; four forces `stop_worker`.
7. **Teardown** — terminates the MCP server (only if the controller started it) and prints a summary.

## Orchestrator Tools (phase-gated decision surface)

**Verification phase tools:**

| Tool | Purpose |
|------|---------|
| `file_finding(...)` | Record a *verified* finding; `verification_notes` must cite reproduction flows. |
| `dismiss_candidate(candidate_id, reason)` | Mark a worker candidate as not-a-finding. |
| `verification_done(summary)` | Signal verification complete; transitions to direction. |

Plus the **full sectool tool surface** (same as workers): `flow_get`, `proxy_poll`, `replay_send`, `request_send`, `diff_flow`, `find_reflected`, `cookie_jar`, `jwt_decode`, `encode`, `decode`, `hash`, `crawl_*`, `oast_*`, `proxy_rule_*`, `proxy_respond_*`, `notes_save`, `notes_list`. The verifier prompt reminds it to prefer non-destructive reproduction and to clean up any rules/responders/sessions it introduces.

**Direction phase tools:**

| Tool | Purpose |
|------|---------|
| `plan_workers(plans)` | Spawn/retarget workers. |
| `continue_worker(worker_id, instruction, progress, autonomous_budget?)` | Keep worker N going with the specified budget. |
| `expand_worker(worker_id, instruction, progress, autonomous_budget?)` | Pivot worker N's plan. |
| `stop_worker(worker_id, reason)` | Retire worker N. |
| `direction_done(summary)` | Signal that all alive workers have a decision. |
| `done(summary)` | End the run. |

Calling a tool in the wrong phase returns an `is_error=True` response directing the orchestrator to transition phases first.

### `autonomous_budget` parameter

`continue_worker` and `expand_worker` accept an optional `autonomous_budget` (integer, 1–20, default 8) that sets how many consecutive autonomous turns the worker may run before escalating back. Typical values:

- **5–10** — productive workers on a clear exploitation path (default 8).
- **3–5** — general exploration.
- **2–3** — exploratory/uncertain assignments where you want to review sooner.

## Worker Tool

| Tool | Purpose |
|------|---------|
| `report_finding_candidate(...)` | Flag a potential vulnerability with proof flow IDs. The orchestrator will verify and, if confirmed, file the formal finding. |

Workers do not write finding documents themselves — that's the orchestrator's job (after verification).

## Findings

Filed findings are written as markdown files to the `--findings-dir` directory:

```
findings/
├── finding-01-reflected-xss-in-search.md
├── finding-02-idor-in-user-api.md
└── ...
```

Each file has Title, Severity, Affected Endpoint, Description, Reproduction Steps, Evidence, Impact, and a **Verification** section in which the orchestrator records the flow IDs and tool calls it used to confirm the issue.

## Safety Bounds

- **Max iterations**: `--max-iterations` caps the outer loop (default 30). Each iteration runs one autonomous worker phase + verification + direction, so an iteration can involve many underlying Claude turns.
- **Cost ceiling**: Optional `--max-cost` flag halts the loop if total USD cost is exceeded. Checked after each phase.
- **Autonomous budget per worker**: 1–20 turns, default 8, settable by the director via `continue_worker` / `expand_worker`.
- **Phase substep caps**: `VERIFICATION_MAX_SUBSTEPS=6`, `DIRECTION_MAX_SUBSTEPS=4` bound each orchestrator phase.
- **Stall detection**: controller-observed via each worker's `escalation_reason`. Three consecutive silent escalations (no tool calls, no new flow IDs) issue a warning in the director prompt; four force a worker stop.
- **Verification required**: findings are only filed after the verifier calls `file_finding` with non-empty `verification_notes`.
