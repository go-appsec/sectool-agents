# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repo layout

This repo houses multiple agent implementations that drive the external [`sectool`](https://github.com/go-appsec/toolbox) MCP server for autonomous security exploration. Each subdirectory is an independent agent with its own runtime/build:

- `secagent/` — Go agent targeting any OpenAI-compatible chat-completions endpoint (most active). Module path `github.com/go-appsec/secagent`, Go 1.25+.
- `claude-controller/` — Python agent built on the Claude Agent SDK; uses an existing `claude` CLI session for auth (no API key).

The root `Makefile` is a pass-through to `secagent/Makefile` only — it does not build, test, or lint `claude-controller/`. `sectool` itself lives in a different repo and must be installed separately (`go install github.com/go-appsec/toolbox/sectool@latest`).

Both agents implement the **same agent contract** (worker reports candidates → verifier reproduces and files → director plans the next iteration over phase-gated tool surfaces), so behavior changes that aren't language-specific should usually land in both. See each agent's README for its flag set, phase substep caps, dedup pipeline, and graceful-shutdown ladder before changing orchestrator behavior.

## Common commands

### secagent (Go)

The Go module lives in `secagent/`, not at the repo root. Either `cd secagent` first or use `make -C secagent ...` / `go ... -C secagent`. The root `Makefile` only forwards `build`, `clean`, `test`, `test-cover`, `bench`, `lint` to `secagent/`.

| Task | Command |
|------|---------|
| Build the binary | `make build` (outputs `bin/secagent` at root and in `secagent/`) |
| Run all Go tests | `make test` (race + cover) |
| Coverage HTML | `make test-cover` |
| Lint | `make lint` (golangci-lint + `go vet`) |
| Benchmarks | `make bench` |
| Single test | `cd secagent && go test ./orchestrator -run TestVerifyDrain` |
| Single subtest | `cd secagent && go test ./orchestrator -run TestVerifyDrain/dismiss_then_done` |
| Single package, verbose | `cd secagent && go test -v -race ./agent` |

### claude-controller (Python)

No Makefile. Install and test from inside `claude-controller/`:

| Task | Command |
|------|---------|
| Install deps | `cd claude-controller && pip install -r requirements.txt` |
| Run all tests | `cd claude-controller && python -m unittest discover tests` |
| Single test module | `cd claude-controller && python -m unittest tests.test_findings` |
| Single test class/method | `cd claude-controller && python -m unittest tests.test_findings.FindingWriterTests.test_dedup` |
| Run the controller | `cd claude-controller && python controller.py --prompt "..." [flags]` |

Tests use stdlib `unittest` (no pytest, no pytest-asyncio); async coroutines are driven via `asyncio.run` inside the test, so plain `python -m unittest` is enough. `tests/conftest.py` only exists to put the package directory on `sys.path` for unittest discovery — it is not pytest config.

## secagent architecture

Reading any single file under `secagent/` underspecifies the system — the multi-agent orchestration crosses package boundaries. Big-picture map:

- **`main.go`** — flag parsing, MCP server bring-up (or attach), agent-factory wiring, signal handling, `orchestrator.Controller.Run`.
- **`orchestrator/`** — the per-iteration state machine. `controller.go` owns the outer loop; iterations run **autonomous worker turns → verification → direction**. Phase-gated tools enforce that each role stays in lane; calling a tool in the wrong phase returns `is_error=true`. Key flows live in `autonomous.go` (worker drain), `verify.go` (verifier drain across substeps), `direct.go` + `director_chat.go` (per-worker decision sub-phase + synthesis sub-phase), `dedup.go` + `merger.go` (candidate dedup pipeline with sync `unique` / `duplicate` and async `merge`), `findings.go` (finding writer with title-slug + endpoint canonicalization + LLM soft-match), `retire.go`, `stall.go`, `narrator.go`. Prompts live in `orchestrator/prompts/`.
- **`agent/`** — the LLM-facing side. `agent.go` defines the `Agent` / `Phase` / `ToolHandler` contracts; `openai_agent.go` + `openai_client.go` + `pool.go` implement an OpenAI-compatible client with a shared concurrency pool; `compact.go` / `compactor.go` / `history.go` manage per-agent message history with watermark-driven compaction; `reasoning.go` / `think.go` handle reasoning blocks; `repair.go` / `retry.go` / `filter_errors.go` classify and re-issue failed tool calls; `fake_agent.go` is the canonical scripted agent for orchestrator tests.
- **`history/`** — long-term per-worker memory: `chronicle.go` is the persistent investigative chronicle that survives across iterations; `compactor.go` / `distill.go` / `summarize.go` produce LLM-driven summaries; `prune.go` / `self_prune.go` apply size-driven pruning; `llmexec.go` is the small LLM dispatcher used by these.
- **`mcp/`** — JSON-RPC client to `sectool mcp`; turns sectool tool definitions into `agent.ToolHandler`s wired through to the orchestrator's per-tool timeout and parallelism caps.
- **`config/`** — flag parsing + validation (caps `--max-workers` at 5, autonomous budget at 1–20, etc.).
- **`cli/`** — terminal color helpers used by the narrator.
- **`util/`** — small string and JSON helpers.

Everything that drives an LLM call is funnelled through the `Agent` interface. The orchestrator builds agents through an `AgentFactory` (currently `OpenAIFactory`) so tests can substitute `FakeAgent` and exercise full phase logic without an LLM. A separate **log model** (`--log-model`) is used for cheap LLM ops (narrator, candidate-dedup classification, async-merge classification); it shares the client pool, only the model identifier differs per request.

The recon-pass mechanics, `autonomous_budget` semantics, dedup pipeline, candidate/finding linkage rules, premature-`end_run` guard, and graceful-shutdown ladder are documented in detail in `secagent/README.md` — read that before changing orchestrator behavior.

## claude-controller architecture

Python single-process orchestrator built on the Claude Agent SDK. Flatter than `secagent/` — every module sits at the package root:

- **`controller.py`** — main orchestrator loop (`asyncio`). Implements the same three-phase iteration as secagent: per-worker autonomous run → verification (multi-substep, capped at `VERIFICATION_MAX_SUBSTEPS=6`) → direction (multi-substep, capped at `DIRECTION_MAX_SUBSTEPS=4`, plus one mandatory self-review substep). Owns MCP bring-up/attach, signal handling, and the worker/verifier/director `ClaudeSDKClient` instances.
- **`tools.py`** — defines the in-process SDK MCP tool servers (`worker_tools` exposing `report_finding_candidate`; `orch_tools` exposing the phase-gated verifier and director surfaces). Tool handlers append to in-process queues; the controller drains them between substeps. Phase gating happens here.
- **`findings.py`** — finding file writer with title-slug + canonicalized-endpoint dedup and pending-candidate tier matching (`match_pending_candidates`). Mirrors secagent's `findings.go` heuristics.
- **`config.py`** — CLI argument parsing + the `MODEL_MAP` from short names (`sonnet`/`opus`/`haiku`) to actual Claude model IDs. Update this map when a new Claude model is released.
- **`prompts/`** — system prompts for the three roles (`worker.py`, `orchestrator_verifier.py`, `orchestrator_director.py`).
- **`tests/`** — `unittest`-based smoke tests using a scripted fake `ClaudeSDKClient`; no network, no real SDK calls. `tests/conftest.py` puts the parent directory on `sys.path`.

Authenticates via the Claude Code CLI's OAuth — there is no API key flag; the `claude` binary on `PATH` must already be logged in.

## Cross-agent considerations

Because both agents implement the same contract, certain invariants need to stay aligned across both codebases when you change them:

- **Phase tool gating** — both reject tools called in the wrong phase with an `is_error` response.
- **Premature-done guard** — both reject `end_run`/`done` before iteration `MIN_ITERATIONS_FOR_DONE` (5) when zero findings have been filed; this exists because models routinely confuse `done` with `direction_done` early on.
- **Autonomous budget** — integer 1–20, default 8, in both.
- **Substep caps** — verification 6, direction 4 in both. Worker count capped at 5 in both.
- **Stall thresholds** — 3 silent escalations → director warning; 4 → forced stop.
- **Finding output format** — both write `finding-NN-<slug>.md` with the same section list ending in a Verification section.

When you change one of these in one agent, check the README and code of the other to keep them in sync.

## Go code style

- Use `var` style for zero-value initialization: `var foo bool` not `foo := false`
- Comments should be concise simple and short phrases rather than full sentences when possible
- Comments should only be added when they describe non-obvious context, not a single line of code
- Godocs should only describe the inputs and outputs, not how the function works
- Follow existing naming conventions and neighboring code style

### Collection handling

Reach for stdlib `slices`/`maps`/`strings` and `github.com/go-analyze/bulk` before writing a manual loop. The patterns below come up often:

- **Clone a slice or map**: `slices.Clone(src)` / `maps.Clone(src)`. Do not `make([]T, len(src))` + `copy(dst, src)` for whole-slice clones (`copy` is still correct for sub-slice writes into an existing buffer).
- **Filter a slice (same element type, no transformation)**: `bulk.SliceFilter(predicate, s)`. Use `bulk.SliceFilterInPlace` when the caller doesn't reuse the input backing array. Use instead of `for _, v := range s { if cond { out = append(out, v) } }`.
- **Slice → map set**: `bulk.SliceToSet(s)` (returns `map[T]struct{}`). Membership tests use the comma-ok form: `if _, ok := set[k]; ok`.
- **Map → slice of keys / values**: `bulk.MapKeysSlice(m)` and `bulk.MapValuesSlice(m)`. Don't write `for k := range m { keys = append(keys, k) }`.
- **Membership check on a slice**: `slices.Contains(s, x)` for comparable element types, `slices.ContainsFunc(s, predicate)` for everything else.

### Go testing

Structure and conventions:
- One `_test.go` file per implementation file that requires testing
- One `func Test<FunctionName>` per target function, using table-driven tests or `t.Run` cases
- Test case names should be at most 3 to 5 words and in lower case with underscores
- Use `t.Parallel()` at test function start when no shared state, but not in the test cases
- Isolated temp directories via `t.TempDir()` when needed
- Context timeouts via `t.Context()` for tests with I/O

Assertions and validation:
- Assertions rely on `testify` (`require` for setup, `assert` for assertions)
- Don't include messages unless the message provides context outside of the test point
- Do NOT use time.Sleep for tests, instead use require.Eventually or deterministic triggers

Test helpers:
- `agent.FakeAgent` is the canonical scripted agent for orchestrator tests — it lets a test pre-program assistant turns, tool calls, and errors, so the verification/direction/autonomous drivers can be exercised without an LLM.
- `secagent/history/testhelpers_test.go` provides shared helpers for history-package tests.

Tests do not touch the network or any real LLM endpoint — they exercise orchestrator phases, queues, finding writer, dedup, async merger, chronicle/iteration history, flow-ID extractor, autonomous-run loop, stall logic, compaction, retry classification, and the verification/direction phase drivers against `FakeAgent`.

## Python (claude-controller) testing

- Tests live under `claude-controller/tests/` using stdlib `unittest`.
- Async code is driven via `asyncio.run(coro)` inside the test method — there is no pytest-asyncio dependency.
- Use the scripted fake `ClaudeSDKClient` pattern already in `tests/test_controller_loop.py` for any new orchestrator-loop coverage; do not call the real SDK or network.
- Write one test class per target unit with descriptive `test_<short_snake_case>` method names.
