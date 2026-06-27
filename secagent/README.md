# sectool Controller - secagent (OpenAI API compatible)

[![Vibe-Scale 3.0(V2|U1|T1): Significant AI with gaps](https://img.shields.io/badge/Vibe--Scale%203.0(V2%7CU1%7CT1)-Significant%20AI%20with%20gaps-ffe066)](https://github.com/vibesdk/vibe-scale/blob/main/scale/vibe-3.md#v2-u1-t1-score-30--significant-ai-with-gaps)

Autonomous security exploration controller written in Go that runs multiple LLM agents against an OpenAI-compatible chat-completions endpoint. Workers, verifier, and director split responsibilities across a shared sectool MCP server; the controller iterates until the director ends the run or `--max-iterations` is hit.

## When to use

Use `secagent` when you want autonomous security exploration driven by any OpenAI-compatible model — local or hosted — distributed as a single Go binary with full process visibility. It is a good fit when:

- **You want local or self-hosted models.** Any OpenAI-compatible chat-completions endpoint with tool-calling support works: OpenAI, vLLM, llama.cpp, LM Studio, Ollama, OpenRouter, etc. You bring the endpoint; secagent does the orchestration.
- **You want visibility into the process.** Every agent turn, tool call, phase transition, candidate dedup verdict, async-merge outcome, stall warning, and finding write lands in a structured JSON line in `--log-file`, so you can audit what the run did and why.
- **You want a single distributable binary.** secagent compiles to one Go binary with no Python or Node runtime to manage, suitable for CI workers and containerized pipelines.

## Architecture

- **Worker(s)** — agents connected to sectool's MCP server plus a small in-process tool (`report_finding_candidate`). Workers execute security tests with sectool (proxy, replay, crawl, OAST, analysis tools) and, when they find something suspicious, call `report_finding_candidate(...)` to flag it. Each worker carries a private investigative chronicle that persists across iterations.
- **Verifier** — dedicated agent whose only job is to reproduce worker-reported candidates using the full sectool tool surface (`flow_get`, `replay_send`, `request_send`, `diff_flow`, `find_reflected`, `proxy_rule_*`, `crawl_*`, `oast_*`, …) and either `file_finding` or `dismiss_candidate`. Composed fresh each iteration, then runs over multiple substeps so it can reflect between reproductions.
- **Director** — dedicated agent whose only job is to decide what each alive worker does next. Per worker it issues a single `decide_worker(action: continue|expand|stop, instruction?, reason?, autonomous_budget?, fork?)` call, then closes the iteration via a separate synthesis call (`plan_workers`, `direction_done`, or `end_run`). Runs every iteration regardless of whether candidates were filed — its job is always worker planning. The controller maintains the director's canonical chat at the orchestrator level (worker activity tagged by id, retired-worker summaries replace dead workers' messages in place); per-worker decision calls install a selectively-compacted view (current worker raw, others compacted) so the director coordinates without drowning in peer detail.

By default, the run begins with an **initial recon** pass — a dedicated recon worker that maps the target's surface area, retires at the end of iteration 1, and whose summary is anchored into every subsequent worker's system prompt and the verifier's per-iter compose. Pass `--skip-recon` to disable this and have the run start with a regular testing worker against `--prompt` (no recon summary anchor for downstream workers). See "How It Works" step 3 for the full mechanics.

A separate **log model** can be configured (`--log-model`) for cheap LLM operations that don't need the main flagship model: the narrator, candidate-dedup classification, and async-merge classification. It shares the main client pool — only the model identifier on each request differs. Defaults to `--model` when unset. Worker-retire and recon-end recaps stay on the main model since those summaries are load-bearing.

Splitting verification and direction into separate clients with separate system prompts forces each role to do its job thoroughly — a single-turn orchestrator tends to short-circuit both.

## Prerequisites

- Go 1.25+ (for building secagent)
- `sectool` available on `$PATH` — secagent shells out to `sectool mcp` when no MCP server is already running on `--mcp-port`. `sectool` is maintained in [go-appsec/toolbox](https://github.com/go-appsec/toolbox) and is not built by this project. Install it with:
  ```bash
  go install github.com/go-appsec/toolbox/sectool@latest
  ```
- An OpenAI-compatible chat-completions endpoint (with tool-calling support)
- The endpoint's API key (when required)

## Installation

From the repo root:

```bash
make build         # builds bin/secagent
```

Then put `bin/` on your `$PATH`, or invoke the binary directly as `bin/secagent`. `sectool` itself is not built by this Makefile — install it separately from [go-appsec/toolbox](https://github.com/go-appsec/toolbox) (see Prerequisites).

## Usage

```bash
bin/secagent \
  --base-url https://api.openai.com/v1 \
  --api-key "$OPENAI_API_KEY" \
  --model gpt-4.1 \
  --prompt "The proxy is configured on port 8181. Explore https://target.example.com for security issues." \
  --proxy-port 8181 \
  --max-iterations 30
```

Single-endpoint local example (vLLM / llama.cpp / LM Studio):

```bash
bin/secagent \
  --base-url http://127.0.0.1:8000/v1 \
  --model qwen2.5-coder:32b \
  --prompt "Explore https://target.example.com for auth issues."
```

Cheaper log-tier model (narrator + candidate dedup) on the same endpoint:

```bash
bin/secagent \
  --base-url https://api.openai.com/v1 --api-key "$OPENAI_API_KEY" \
  --model gpt-4.1 --log-model gpt-4.1-mini \
  --prompt "Explore https://target.example.com."
```

## CLI Arguments

**Connection**

| Flag | Default | Description |
|------|---------|-------------|
| `--base-url` | - | OpenAI-compatible base URL |
| `--api-key` | - | Optional API key |
| `--model` | - | Main model ID (workers, verifier, director, boundary-summarize) |
| `--log-model` | (= `--model`) | Model ID for narrator, candidate dedup, async-merge classify |
| `--agent-pool-size` | `4` | Concurrent model-request bound (shared pool) |

**Context / compaction**

| Flag | Default | Description |
|------|---------|-------------|
| `--max-context` | `200000` | Main-model context window in tokens |
| `--log-max-context` | (= `--max-context`) | Log-model context window in tokens |
| `--tool-result-max-bytes` | `8192` | Per-tool-result truncation cap |
| `--compaction-high-watermark` | `0.80` | Fraction of context that triggers compaction |
| `--compaction-low-watermark` | `0.40` | Compaction target fraction |
| `--compaction-keep-turns` | `4` | Trailing turns never compacted |
| `--keep-think-turns` | `0` (auto) | Assistant messages to preserve `<think>` blocks on when replaying history. `0` auto-picks 4 if max-context ≤ 128k else 8 |

**Sectool**

| Flag | Default | Description |
|------|---------|-------------|
| `--proxy-port` | `8181` | Port for sectool's native proxy |
| `--mcp-port` | `9119` | Port for sectool's MCP server (auto-attaches when one is already running) |
| `--sectool-bin` | `""` | Path to the sectool binary. Empty falls back to a binary co-located with secagent, then `$PATH` |
| `--skip-version-check` | `false` | Skip the best-effort sectool version staleness check at startup. See "Sectool version check" below |

**Loop**

| Flag | Default | Description |
|------|---------|-------------|
| `--prompt` | - | **Required.** Initial task prompt for the first worker |
| `--max-iterations` | `30` | Hard cap on outer loop iterations |
| `--max-workers` | `4` | Maximum parallel workers (capped at 5) |
| `--autonomous-budget` | `8` | Turns per worker per iteration (1–20) |
| `--turn-timeout` | `10m` | Per-turn (per chat-completion call) context timeout |
| `--per-tool-timeout` | `5m` | Per-tool-call context timeout |
| `--max-parallel-tools` | `4` | Max concurrent in-flight tool calls per assistant response |
| `--max-turns-per-agent` | `100` | Hard cap per Drain chain |
| `--findings-dir` | `./findings` | Directory for finding report files |
| `--skip-recon` | `false` | Skip the initial recon pass; the run starts with a normal testing worker against `--prompt`. See "How It Works" step 3 |

**Stall detection**

| Flag | Default | Description |
|------|---------|-------------|
| `--stall-warn-after` | `3` | Silent runs before director warning |
| `--stall-stop-after` | `4` | Silent runs before force-stop |

**Logging / narration**

| Flag | Default | Description |
|------|---------|-------------|
| `--narrate-interval` | `5m` | Min interval between async narrator summaries (0 disables). Per-summary timeout is auto-computed as `max(2 × narrate-interval, 15m)`. |
| `--log-file` | `secagent.log` | Structured JSON log destination |

## Sectool version check

The resolved or configured sectool is used for both the version check and the MCP launch. Unless `--skip-version-check` is set, secagent then performs a best-effort staleness check:

- `sectool --version` is compared with the latest tagged release.
- If a strictly newer release exists **and** secagent is about to spawn `sectool` itself, secagent exits with a `go install github.com/go-appsec/toolbox/sectool@latest` message. When attaching to an already-running MCP (see below) the same condition is logged and startup continues.
- Results are cached at `<TMPDIR>/secagent-state.json` under `sectool_version_check` so subsequent startups are faster.

## Using with an Existing MCP Server

secagent probes `--mcp-port` at startup. If a sectool MCP server is already serving on that port, secagent attaches to it (no child process started, no teardown on exit). Otherwise it launches `sectool mcp` from `$PATH` and tears it down at exit.

```bash
# Start the MCP server separately
sectool mcp --proxy-port 8181

# In another terminal, run secagent against it — no special flag required
bin/secagent \
  --base-url https://api.openai.com/v1 --api-key "$OPENAI_API_KEY" \
  --model gpt-4.1 \
  --prompt "Explore https://target.example.com for auth vulnerabilities." \
  --proxy-port 8181 --mcp-port 9119
```

## How It Works

```
   --prompt
      │
      ▼
   recon problem
      │
      ▼
   ┌──────────► workers explore ──► candidates ──► verifier ──┬──► file_finding
   │              │                                           │
   │              │                                           └──► dismiss
   │              ▼
   └───────── director steers
              continue / expand / stop / spawn — or end_run to exit
```

Each loop around the cycle is one **iteration**. The controller keeps iterating until the director calls `end_run` or `--max-iterations` is hit. The `recon problem` step is the initial recon worker (iter 1); with `--skip-recon` the run jumps straight into the workers/director loop against `--prompt`.

## Worker Tool

| Tool | Purpose |
|------|---------|
| `report_finding_candidate(...)` | Flag a potential vulnerability with proof flow IDs. The verifier will reproduce and, if confirmed, file the formal finding. |

Workers do not write finding documents themselves — that's the verifier's job (after reproduction).

### Candidate dedup pipeline

Every `report_finding_candidate` call runs through a cheap LLM dedup check (log model) against the digests of already-filed findings before the candidate enters the pool. Three outcomes:

- **unique** — candidate enters the pool and is presented to the verifier next phase.
- **duplicate** — rejected at the tool boundary; the worker is told which finding already covers it and to pivot to a different angle.
- **merge** — acknowledged synchronously to the worker; the candidate's evidence is queued onto a bounded background goroutine pool that opens the matched finding, calls the log model again to merge the new evidence in, and writes the result. The controller waits on outstanding merges at shutdown so no work is lost.

Findings filed by the verifier go through a similar dedup pass before being written to disk (`writer.MatchesFiled` deterministic match plus an LLM review for soft matches), and pending candidates that aren't explicitly linked via `supersedes_candidate_ids` are tier-matched (title+endpoint, then endpoint-only, then title-only) so the verifier can leave the linkage implicit when the relationship is obvious.

## Orchestrator Tools (phase-gated decision surface)

**Verification phase tools:**

| Tool | Purpose |
|------|---------|
| `file_finding(...)` | Record a *verified* finding; `verification_notes` must describe how the issue was reproduced. Optional `supersedes_candidate_ids` explicitly links the finding to the candidate(s) it covers. Optional `follow_up_hint` advises the director on adjacent angles to probe. |
| `dismiss_candidate(candidate_id, reason)` | Mark a worker candidate as not-a-finding. Optional `follow_up_hint` advises the director. |
| `verification_done(summary)` | Signal verification complete; transitions to direction. |

Plus the **full sectool tool surface** (same as workers): `flow_get`, `proxy_poll`, `replay_send`, `request_send`, `diff_flow`, `find_reflected`, `cookie_jar`, `jwt_decode`, `encode`, `decode`, `hash`, `crawl_*`, `oast_*`, `proxy_rule_*`, `proxy_respond_*`, `notes_save`, `notes_list`. The verifier prompt directs it to prefer non-destructive reproduction and clean up any rules/responders/sessions it introduces.

**Direction phase tools:**

The direction phase has two sub-phases. The decision sub-phase is per-worker: the controller prompts the director once per alive worker and the director must call `decide_worker` exactly once for that worker. The synthesis sub-phase is one final call that closes the iteration.

Per-worker decision tool:

| Tool | Purpose |
|------|---------|
| `decide_worker(worker_id, action, instruction?, reason?, autonomous_budget?, fork?)` | The unified per-worker decision. `action="continue"` keeps the worker on its current angle (`instruction` is the next-iter directive). `action="expand"` pivots to a new angle (`instruction` is the new directive). `action="stop"` retires the worker (`reason` explains why). Optional `autonomous_budget` (1–20) sets the next iteration's turn cap. Optional `fork={new_worker_id, instruction}` spawns a child worker that inherits this worker's chronicle. |

Synthesis tools (one call after all per-worker decisions):

| Tool | Purpose |
|------|---------|
| `plan_workers(plans)` | Spawn fresh workers and/or retarget existing alive workers. Each entry's `worker_id` must be either an existing alive worker (→ retarget) or an integer not in the alive or completed set (→ spawn). |
| `direction_done(summary)` | Signal direction phase complete. **Use this to close almost every iteration.** |
| `end_run(summary)` | End the entire run. Rejected as premature when called before iteration `MinIterationsForDone` (5) with zero findings filed — local models that conflate `end_run` with `direction_done` get a clear error pointing them at the right tool. Also rejected if any alive worker hasn't been stopped. |

Calling a tool in the wrong phase returns an `is_error=true` response directing the orchestrator to transition phases first.

### `autonomous_budget` parameter

`decide_worker` accepts an optional `autonomous_budget` (integer, 1–20, default 8) that sets how many consecutive autonomous turns the worker may run before escalating back. Typical values:

- **8–15** — productive workers on a clear exploitation path.
- **5–8** — general exploration (default).
- **2–4** — exploratory/uncertain assignments where you want to review sooner.

## What the director sees

Per iteration the director receives the verification summary, every worker's autonomous-run transcript for the iteration, a findings-so-far recap, optional verifier follow-up hints, optional stall warnings, and a **recent worker history block** rendered from a per-worker ring (last 6 iterations). Each entry includes the angle, an outcome token, tool-call count, and flow count. Outcome tokens (precedence top-to-bottom):

| Token | Meaning |
|-------|---------|
| `stopped` | Worker was stopped this iteration (no longer alive). |
| `finding` | Verifier explicitly linked a filed finding to one of this worker's candidates via `supersedes_candidate_ids`. |
| `possible-finding` | Verifier filed a finding that heuristically matches one of this worker's candidates (title+endpoint tier match) but didn't explicitly link it. The director should follow up rather than assume coverage — a finding outcome should be explicit. |
| `dismissed` | Verifier dismissed a candidate from this worker. |
| `candidate` | Worker reported a candidate that's still pending at iter end. |
| `silent` / `error` / `budget` | Escalation reason from a worker that didn't produce a candidate. |

The director's system prompt also defines an **angle exhaustion** rule: when a worker's history shows the same or near-identical angle across 2+ iterations with no finding filed, treat it as exhausted and pivot or stop — don't re-issue a lightly-reworded variant.

## Findings

Filed findings are written as markdown files to `--findings-dir`:

```
findings/
├── finding-01-reflected-xss-in-search.md
├── finding-02-idor-in-user-api.md
└── ...
```

Each file has Title, Severity, Affected Endpoint, Description, Reproduction Steps, Evidence, Impact, and a **Verification** section in which the verifier records how it reproduced the issue. Findings are deduplicated by title-slug and canonicalized endpoint plus an LLM soft-match review before write; merges from later iterations re-open and rewrite the matched file via the log model.

## Logs

`--log-file` (default `secagent.log`) receives a structured JSON event per line covering server lifecycle, agent turns, phase transitions, decisions, stalls, candidate dedup verdicts, async-merge outcomes, summarize callbacks, and findings. The child sectool MCP server's stdout/stderr go to `sectool-mcp.log` in the working directory.

## Safety Bounds

- **Max iterations**: `--max-iterations` caps the outer loop (default 30). Each iteration runs one autonomous worker phase + verification + direction, so an iteration involves many underlying model turns.
- **Autonomous budget per worker**: 1–20 turns, default 8, settable per worker by the director via `decide_worker(autonomous_budget=...)`.
- **Phase substep caps**: `VerificationMaxSubsteps=6`; per-worker `decide_worker` drain capped at `decisionDrainMaxRounds=4`.
- **Per-agent turn cap**: `--max-turns-per-agent` (default 100) bounds any single Drain chain.
- **Stall detection**: configurable via `--stall-warn-after` / `--stall-stop-after`.
- **Per-turn timeout**: `--turn-timeout` (default 10m) bounds each model call. `--per-tool-timeout` (default 5m) bounds each tool dispatch.
- **Max workers**: capped at 5 by `config.Parse`.
- **Verification required**: findings are only filed after the verifier calls `file_finding` with non-empty `verification_notes`.
- **Premature end_run guard**: rejected before iteration 5 when zero findings have been filed; also rejected when alive workers haven't been stopped.

## Graceful Shutdown (Ctrl-C / SIGTERM)

secagent installs a triple-Ctrl-C / SIGTERM handler so an in-flight run can be wound down without losing already-collected work:

1. **First signal** — finishes verification of any pending candidates and skips the next direction phase. Verified findings are written to `--findings-dir` as normal.
2. **Second signal** — dumps every still-pending candidate to disk as an unverified record so the worker's evidence isn't lost.
3. **Third signal** — force-exits with code 130. No further teardown.

The sectool MCP server is only torn down if secagent launched it; an attached pre-existing server is left running. Outstanding async finding-merge goroutines are awaited at exit.

## Running the tests

From the repo root:

```bash
make test            # go test -race -cover ./...
make test-cover      # coverage profile + HTML report
```

Or directly inside the secagent module:

```bash
cd secagent && go test ./...
```

The tests do not touch the network or any real LLM endpoint — they exercise the orchestrator phases, candidate/decision queues, finding writer, dedup pipeline, async merger, chronicle/iteration-history derivation, flow-ID extractor, autonomous-run loop, stall logic, compaction, retry classification, and the verification/direction phase drivers against a scripted `FakeAgent`.
