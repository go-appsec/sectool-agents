package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/go-analyze/bulk"

	"github.com/go-appsec/sectool-agents/secagent/agent"
	"github.com/go-appsec/sectool-agents/secagent/orchestrator/prompts"
	"github.com/go-appsec/sectool-agents/secagent/util"
)

// decideAction* are the valid action enum values for decide_worker.
const (
	decideActionContinue = "continue"
	decideActionExpand   = "expand"
	decideActionStop     = "stop"
)

// Severities for validation.
var severities = map[string]bool{
	"critical":      true,
	"high":          true,
	"medium":        true,
	"low":           true,
	"informational": true,
}

// MergeSubmitter schedules a background merge of a worker-reported
// candidate into matchedFilename. Pass nil to disable async merge.
type MergeSubmitter interface {
	Submit(matchedFilename string, incoming AddInput)
}

// WorkerToolDefs returns the per-worker tool set (report_finding_candidate).
// dedupReviewer (optional) classifies candidates against filed findings; merger (optional) handles "merge" verdicts.
func WorkerToolDefs(candidates *CandidatePool, writer *FindingWriter,
	workerID int, dedupReviewer CandidateDedupReviewer, merger MergeSubmitter) []agent.ToolDef {
	return []agent.ToolDef{
		{
			Name: "report_finding_candidate",
			Description: `Report a potential security finding for orchestrator verification.
Include proof flow IDs from your testing (replay_send, request_send, or proxy_poll).
Do NOT write a full finding document — the orchestrator will reproduce the issue and file the formal finding.
Returns a candidate_id confirmation.`,
			Schema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"title":    map[string]any{"type": "string", "description": "Concise vulnerability name"},
					"severity": map[string]any{"type": "string", "enum": []string{"critical", "high", "medium", "low", "informational"}},
					"endpoint": map[string]any{"type": "string", "description": "Affected endpoint path + method"},
					"flow_ids": map[string]any{
						"type":        "array",
						"items":       map[string]any{"type": "string"},
						"description": "Proof flow IDs. At least one required.",
					},
					"summary":           map[string]any{"type": "string"},
					"evidence_notes":    map[string]any{"type": "string"},
					"reproduction_hint": map[string]any{"type": "string"},
				},
				"required": []string{
					"title", "severity", "endpoint", "flow_ids", "summary",
					"evidence_notes", "reproduction_hint",
				},
			},
			Handler: func(ctx context.Context, args json.RawMessage) agent.ToolResult {
				var in struct {
					Title            string   `json:"title"`
					Severity         string   `json:"severity"`
					Endpoint         string   `json:"endpoint"`
					FlowIDs          []string `json:"flow_ids"`
					Summary          string   `json:"summary"`
					EvidenceNotes    string   `json:"evidence_notes"`
					ReproductionHint string   `json:"reproduction_hint"`
				}
				if err := unmarshalToolArgs(args, &in); err != nil {
					return agent.ToolResult{Text: "Rejected: invalid arguments: " + err.Error(), IsError: true}
				}
				sev := strings.ToLower(in.Severity)
				if !severities[sev] {
					return agent.ToolResult{
						Text:    "Rejected: severity must be one of critical/high/medium/low/informational.",
						IsError: true,
					}
				}
				if msg := requiredFieldsErr(map[string]string{
					"title": in.Title, "endpoint": in.Endpoint, "summary": in.Summary,
					"evidence_notes": in.EvidenceNotes, "reproduction_hint": in.ReproductionHint,
				}); msg != "" {
					return agent.ToolResult{Text: msg, IsError: true}
				}
				if len(in.FlowIDs) == 0 {
					return agent.ToolResult{
						Text:    "Rejected: flow_ids must be a non-empty array.",
						IsError: true,
					}
				}
				if slices.ContainsFunc(in.FlowIDs, func(id string) bool { return strings.TrimSpace(id) == "" }) {
					return agent.ToolResult{
						Text:    "Rejected: flow_ids entries must be non-empty strings.",
						IsError: true,
					}
				}
				addIn := AddInput{
					WorkerID:         workerID,
					Title:            strings.TrimSpace(in.Title),
					Severity:         sev,
					Endpoint:         strings.TrimSpace(in.Endpoint),
					FlowIDs:          in.FlowIDs,
					Summary:          strings.TrimSpace(in.Summary),
					EvidenceNotes:    strings.TrimSpace(in.EvidenceNotes),
					ReproductionHint: strings.TrimSpace(in.ReproductionHint),
				}
				if writer != nil {
					if rej, ok := dedupRejectOrMerge(ctx, dedupReviewer, merger, writer, addIn); ok {
						return rej
					}
				}
				cid := candidates.Add(addIn)
				return agent.ToolResult{
					Text: fmt.Sprintf(
						"Candidate %s recorded. The orchestrator will verify and, if confirmed, file the formal finding. Continue your testing.",
						cid,
					),
				}
			},
		},
	}
}

// dedupRejectOrMerge returns (result, true) when in is a duplicate or
// has been queued for merge, or (_, false) when it should be added.
func dedupRejectOrMerge(ctx context.Context, dedupReviewer CandidateDedupReviewer,
	merger MergeSubmitter, writer *FindingWriter, in AddInput) (agent.ToolResult, bool) {
	if dedupReviewer == nil {
		if matched, path, ok := writer.MatchesFiled(in.Title, in.Endpoint); ok {
			return agent.ToolResult{
				Text: fmt.Sprintf(
					"Rejected: matches already-filed finding %q (%s). Pick a different angle — do not re-report this issue.",
					matched, filepath.Base(path),
				),
				IsError: true,
			}, true
		}
		return agent.ToolResult{}, false
	}
	digests := writer.Digests()
	if len(digests) == 0 {
		return agent.ToolResult{}, false
	}
	verdict, err := dedupReviewer.ClassifyCandidate(ctx, in, digests)
	if err != nil {
		// Fail-open on classifier errors: let the candidate enter the pool
		// and rely on the verifier-side dedup pipeline as the safety net.
		return agent.ToolResult{}, false
	}
	switch verdict.Action {
	case dedupActionDuplicate:
		return agent.ToolResult{
			Text: fmt.Sprintf(
				"Rejected: matches already-filed finding %s. Pick a different angle — your candidate is fully covered there.",
				verdict.MatchedFilename,
			),
			IsError: true,
		}, true
	case dedupActionMerge:
		if merger == nil {
			// No async merge available; degrade to a duplicate-style reject.
			return agent.ToolResult{
				Text: fmt.Sprintf(
					"Rejected: matches already-filed finding %s. Pick a different angle — your candidate is fully covered there.",
					verdict.MatchedFilename,
				),
				IsError: true,
			}, true
		}
		merger.Submit(verdict.MatchedFilename, in)
		return agent.ToolResult{
			Text: fmt.Sprintf(
				"Match detected with finding %s. Your evidence will be merged into that finding in the background — pick a different angle next.",
				verdict.MatchedFilename,
			),
		}, true
	}
	return agent.ToolResult{}, false
}

// BashToolDef returns an unrestricted shell-execution tool. maxResultBytes caps
// the output returned to the model (<= 0 disables the cap). bg (optional)
// enables background=true; nil rejects it. Command filtering is deliberately
// absent — access is gated by --allow-bash at the controller level.
func BashToolDef(maxResultBytes int, bg *BashBackground) agent.ToolDef {
	return agent.ToolDef{
		Name: "bash",
		Description: `Execute an arbitrary shell command on the host running secagent via ` +
			`bash -c. There are no command restrictions. Stdout and stderr are returned ` +
			`combined; the result flags non-zero exit codes as errors. ` +
			`Set background=true only when necessary (a command that must outlive this call); ` +
			`it then returns the pid and stdout/stderr log file paths immediately. ` +
			`Use when the sectool tools cannot accomplish the task or the instruction calls for it.`,
		Schema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"command": map[string]any{
					"type":        "string",
					"description": "Shell command line to execute (interpreted by bash)",
				},
				"background": map[string]any{
					"type":        "boolean",
					"description": "Run detached and return immediately with the pid plus stdout/stderr log file paths. Only use when necessary — when a command must outlive this tool call (long polls, listeners, servers). Tail the returned logs to review progress; stop the job with `kill -- -PID` (targets the whole process group) when done.",
				},
			},
			"required": []string{"command"},
		},
		Handler: func(ctx context.Context, args json.RawMessage) agent.ToolResult {
			var in struct {
				Command    string `json:"command"`
				Background bool   `json:"background"`
			}
			if err := unmarshalToolArgs(args, &in); err != nil {
				return agent.ToolResult{
					Text:    "Rejected: invalid arguments: " + err.Error(),
					IsError: true,
				}
			}
			if strings.TrimSpace(in.Command) == "" {
				return agent.ToolResult{
					Text:    "Rejected: 'command' must be a non-empty shell command line.",
					IsError: true,
				}
			}
			if in.Background {
				if bg == nil {
					return agent.ToolResult{
						Text:    "Rejected: background execution is unavailable in this run.",
						IsError: true,
					}
				}
				text, err := bg.Start(ctx, in.Command)
				if err != nil {
					return agent.ToolResult{
						Text:    "Command failed to start: " + err.Error(),
						IsError: true,
					}
				}
				return agent.ToolResult{Text: text}
			}
			cmd := exec.CommandContext(ctx, "bash", "-c", in.Command)
			// own process group so the per-tool timeout kills the whole child
			// tree, not just the bash child it can see
			armProcessGroup(cmd, killWaitTimeout)
			var combined bytes.Buffer
			cmd.Stdout = &combined
			cmd.Stderr = &combined
			runErr := cmd.Run()
			out := strings.TrimSpace(combined.String())
			if out == "" {
				out = "(no output)"
			}
			var exitErr *exec.ExitError
			if errors.As(runErr, &exitErr) {
				status := -1
				if code := exitErr.ExitCode(); code >= 0 {
					status = code
				}
				return agent.ToolResult{
					Text:    fmt.Sprintf("Command exited with status %d:\n%s", status, out),
					IsError: true,
				}
			}
			if runErr != nil {
				// ctx cancel, bash missing, etc.
				return agent.ToolResult{
					Text:    "Command failed to run: " + runErr.Error(),
					IsError: true,
				}
			}
			if maxResultBytes > 0 && len(out) > maxResultBytes {
				out = util.TruncateBytes(out, maxResultBytes) +
					fmt.Sprintf("\n…(truncated: %d of %d bytes shown. Narrow the command output — e.g. pipe through head/tail/grep — then call again.)", maxResultBytes, len(out))
			}
			return agent.ToolResult{Text: out}
		},
	}
}

// VerifierToolDefs returns the in-process verifier tool set (file_finding, dismiss_candidate, verification_done).
// candidates (required) validates candidate references at the tool boundary.
func VerifierToolDefs(decisions *DecisionQueue, candidates *CandidatePool) []agent.ToolDef {
	reject := func(name string) agent.ToolResult {
		cur := decisions.Phase()
		return agent.ToolResult{
			Text: fmt.Sprintf(
				"Rejected: `%s` is not allowed in phase '%s'. Expected phase 'verification'.",
				name, cur,
			),
			IsError: true,
		}
	}

	return []agent.ToolDef{
		{
			Name: "file_finding",
			Description: `File a verified security finding. Call ONLY after independently reproducing
the issue with sectool tools. All fields must be session-agnostic: describe endpoints, payloads,
headers, and observed behavior — never cite flow IDs, OAST session IDs, or other ephemeral test state.`,
			Schema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"title":       map[string]any{"type": "string"},
					"severity":    map[string]any{"type": "string", "enum": []string{"critical", "high", "medium", "low", "informational"}},
					"endpoint":    map[string]any{"type": "string"},
					"description": map[string]any{"type": "string"},
					"reproduction_steps": map[string]any{
						"type":        "string",
						"description": "Step-by-step reproduction using endpoint, method, headers, and payload — no flow IDs or session references.",
					},
					"evidence": map[string]any{
						"type":        "string",
						"description": "Observable proof: response content, status codes, headers, behavior — no flow IDs or session references.",
					},
					"impact": map[string]any{"type": "string"},
					"verification_notes": map[string]any{
						"type":        "string",
						"description": "How you reproduced the issue: tools used, mutations applied, what you observed — no flow IDs or session IDs.",
					},
					"supersedes_candidate_ids": map[string]any{
						"type":  "array",
						"items": map[string]any{"type": "string"},
					},
					"follow_up_hint": map[string]any{
						"type":        "string",
						"description": "Optional one-line hint for the director: a related angle, variant, or adjacent endpoint worth probing next. Advisory only; omit if nothing stands out.",
					},
				},
				"required": []string{
					"title", "severity", "endpoint", "description",
					"reproduction_steps", "evidence", "impact", "verification_notes",
				},
			},
			Handler: func(ctx context.Context, args json.RawMessage) agent.ToolResult {
				if decisions.Phase() != agent.PhaseVerification {
					return reject("file_finding")
				}
				var in struct {
					Title                  string   `json:"title"`
					Severity               string   `json:"severity"`
					Endpoint               string   `json:"endpoint"`
					Description            string   `json:"description"`
					ReproductionSteps      string   `json:"reproduction_steps"`
					Evidence               string   `json:"evidence"`
					Impact                 string   `json:"impact"`
					VerificationNotes      string   `json:"verification_notes"`
					SupersedesCandidateIDs []string `json:"supersedes_candidate_ids"`
					FollowUpHint           string   `json:"follow_up_hint"`
				}
				if err := unmarshalToolArgs(args, &in); err != nil {
					return agent.ToolResult{Text: "Rejected: invalid arguments: " + err.Error(), IsError: true}
				}
				sev := strings.ToLower(in.Severity)
				if !severities[sev] {
					return agent.ToolResult{
						Text:    "Rejected: severity must be one of critical/high/medium/low/informational.",
						IsError: true,
					}
				}
				if msg := requiredFieldsErr(map[string]string{
					"title": in.Title, "endpoint": in.Endpoint, "description": in.Description,
					"reproduction_steps": in.ReproductionSteps, "evidence": in.Evidence, "impact": in.Impact,
				}); msg != "" {
					return agent.ToolResult{Text: msg, IsError: true}
				}
				notes := strings.TrimSpace(in.VerificationNotes)
				if notes == "" {
					return agent.ToolResult{
						Text:    "Rejected: verification_notes must describe how you reproduced the issue with sectool tools.",
						IsError: true,
					}
				}
				supersedes := make([]string, len(in.SupersedesCandidateIDs))
				for i, id := range in.SupersedesCandidateIDs {
					supersedes[i] = strings.TrimSpace(id)
				}
				if bad := bulk.SliceFilter(func(id string) bool { return !candidates.Markable(id) }, supersedes); len(bad) > 0 {
					return agent.ToolResult{
						Text: fmt.Sprintf(
							"Rejected: supersedes_candidate_ids references unknown or already-resolved candidate(s): %s. Pending candidates: %s.",
							strings.Join(bad, ", "), pendingCandidateIDs(candidates),
						),
						IsError: true,
					}
				}
				f := FindingFiled{
					Title:                  strings.TrimSpace(in.Title),
					Severity:               sev,
					Endpoint:               strings.TrimSpace(in.Endpoint),
					Description:            strings.TrimSpace(in.Description),
					ReproductionSteps:      strings.TrimSpace(in.ReproductionSteps),
					Evidence:               strings.TrimSpace(in.Evidence),
					Impact:                 strings.TrimSpace(in.Impact),
					VerificationNotes:      notes,
					SupersedesCandidateIDs: supersedes,
					FollowUpHint:           strings.TrimSpace(in.FollowUpHint),
				}
				decisions.AddFinding(f)
				return agent.ToolResult{Text: fmt.Sprintf("Finding '%s' recorded for persistence.", f.Title)}
			},
		},
		{
			Name:        "dismiss_candidate",
			Description: `Mark a worker-reported finding candidate as not a real issue. Provide a short reason.`,
			Schema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"candidate_id": map[string]any{"type": "string"},
					"reason":       map[string]any{"type": "string"},
					"follow_up_hint": map[string]any{
						"type":        "string",
						"description": "Optional one-line hint for the director: a related angle or real lead this dead-end points toward. Advisory only; omit if nothing stands out.",
					},
				},
				"required": []string{"candidate_id", "reason"},
			},
			Handler: func(ctx context.Context, args json.RawMessage) agent.ToolResult {
				if decisions.Phase() != agent.PhaseVerification {
					return reject("dismiss_candidate")
				}
				var in struct {
					CandidateID  string `json:"candidate_id"`
					Reason       string `json:"reason"`
					FollowUpHint string `json:"follow_up_hint"`
				}
				if err := unmarshalToolArgs(args, &in); err != nil {
					return agent.ToolResult{Text: "Rejected: invalid arguments.", IsError: true}
				}
				cid := strings.TrimSpace(in.CandidateID)
				reason := strings.TrimSpace(in.Reason)
				if cid == "" || reason == "" {
					return agent.ToolResult{
						Text:    "Rejected: candidate_id and reason required.",
						IsError: true,
					}
				}
				if !candidates.Markable(cid) {
					return agent.ToolResult{
						Text: fmt.Sprintf(
							"Rejected: candidate %s is unknown or already resolved. Pending candidates: %s.",
							cid, pendingCandidateIDs(candidates),
						),
						IsError: true,
					}
				}
				decisions.AddDismissal(CandidateDismissal{
					CandidateID:  cid,
					Reason:       reason,
					FollowUpHint: strings.TrimSpace(in.FollowUpHint),
				})
				return agent.ToolResult{Text: fmt.Sprintf("Candidate %s dismissal recorded.", cid)}
			},
		},
		{
			Name:        "verification_done",
			Description: `Signal that the verification phase is complete.`,
			Schema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"summary": map[string]any{"type": "string"},
				},
				"required": []string{"summary"},
			},
			Handler: func(ctx context.Context, args json.RawMessage) agent.ToolResult {
				if decisions.Phase() != agent.PhaseVerification {
					return reject("verification_done")
				}
				var in struct {
					Summary string `json:"summary"`
				}
				if err := unmarshalToolArgs(args, &in); err != nil {
					return agent.ToolResult{Text: "Rejected: invalid arguments.", IsError: true}
				}
				s := strings.TrimSpace(in.Summary)
				if s == "" {
					return agent.ToolResult{Text: "Rejected: summary is required.", IsError: true}
				}
				decisions.SetVerificationDone(s)
				return agent.ToolResult{Text: "Verification phase complete."}
			},
		},
	}
}

// TakenIDsFunc returns worker IDs that are not eligible for reuse
// (alive or completed).
type TakenIDsFunc func() map[int]bool

// DecisionToolDefs returns the per-worker decision tool set (decide_worker).
// takenIDs validates fork.new_worker_id; both takenIDs and log may be nil.
func DecisionToolDefs(decisions *DecisionQueue, takenIDs TakenIDsFunc, log *Logger) []agent.ToolDef {
	reject := func(name string) agent.ToolResult {
		cur := decisions.Phase()
		return agent.ToolResult{
			Text: fmt.Sprintf(
				"Rejected: `%s` is not allowed in phase '%s'. Expected phase 'direction'.",
				name, cur,
			),
			IsError: true,
		}
	}
	return []agent.ToolDef{
		{
			Name: "decide_worker",
			Description: `Decide what worker N does next iteration. ` +
				`Call exactly ONCE per per-worker decision prompt; the worker_id you pass MUST match the worker the prompt asked about. ` +
				`action="continue" keeps the worker on its current angle (instruction is the next-iter directive). ` +
				`action="expand" pivots to a new angle (instruction is the new directive). ` +
				`action="stop" retires the worker (reason explains why). ` +
				`Optional fork={new_worker_id, instruction} spawns a child worker that inherits this worker's chronicle and gets the steering instruction; pick a new_worker_id NOT in the alive or completed set.`,
			Schema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"worker_id":   map[string]any{"type": "integer", "minimum": 1},
					"action":      map[string]any{"type": "string", "enum": []string{"continue", "expand", "stop"}},
					"instruction": map[string]any{"type": "string", "description": "Required for continue/expand."},
					"reason":      map[string]any{"type": "string", "description": "Required for stop."},
					"autonomous_budget": map[string]any{
						"type":    "integer",
						"minimum": 1,
						"maximum": maxAutonomousBudget,
						"description": fmt.Sprintf(
							"Consecutive autonomous turns this worker may run before escalating back "+
								"for review. Use 5-10 for productive workers on a clear path, 2-3 for "+
								"exploratory or uncertain assignments. Default %d.",
							defaultAutonomousBudget,
						),
					},
					"fork": map[string]any{
						"type": "object",
						"properties": map[string]any{
							"new_worker_id": map[string]any{"type": "integer", "minimum": 1},
							"instruction":   map[string]any{"type": "string"},
						},
						"required": []string{"new_worker_id", "instruction"},
					},
				},
				"required": []string{"worker_id", "action"},
			},
			Handler: func(ctx context.Context, args json.RawMessage) agent.ToolResult {
				if decisions.Phase() != agent.PhaseDirection {
					return reject("decide_worker")
				}
				var in struct {
					WorkerID         int    `json:"worker_id"`
					Action           string `json:"action"`
					Instruction      string `json:"instruction"`
					Reason           string `json:"reason"`
					AutonomousBudget int    `json:"autonomous_budget"`
					Fork             *struct {
						NewWorkerID int    `json:"new_worker_id"`
						Instruction string `json:"instruction"`
					} `json:"fork"`
				}
				if err := unmarshalToolArgs(args, &in); err != nil {
					return agent.ToolResult{Text: "Rejected: invalid arguments: " + err.Error(), IsError: true}
				}
				if in.WorkerID < 1 {
					return agent.ToolResult{Text: "Rejected: worker_id must be >= 1.", IsError: true}
				}
				asked := decisions.AskedWorkerID()
				if asked > 0 && in.WorkerID != asked {
					log.Log(tagDecision, "worker-id-mismatch", map[string]any{
						"asked":    asked,
						"received": in.WorkerID,
					})
					return agent.ToolResult{
						Text: fmt.Sprintf(
							"Rejected: this prompt asked about worker %d but decide_worker received worker_id=%d. Re-issue with worker_id=%d.",
							asked, in.WorkerID, asked,
						),
						IsError: true,
					}
				}
				if decisions.HasDecisionFor(in.WorkerID) {
					return agent.ToolResult{
						Text: fmt.Sprintf(
							"Rejected: worker %d already has a decision recorded this phase — decide_worker must be called exactly once per worker. No change was made; move on to the next worker's prompt.",
							in.WorkerID,
						),
						IsError: true,
					}
				}
				action := strings.ToLower(strings.TrimSpace(in.Action))
				switch action {
				case decideActionContinue:
					// continue: empty instruction means prompts.DefaultContinueDirective at apply time
					if strings.TrimSpace(in.Instruction) == "" {
						in.Instruction = prompts.DefaultContinueDirective
					}
				case decideActionExpand:
					if strings.TrimSpace(in.Instruction) == "" {
						return agent.ToolResult{
							Text:    "Rejected: instruction is required for action=expand (use action=continue to keep the existing angle).",
							IsError: true,
						}
					}
				case decideActionStop:
					if strings.TrimSpace(in.Reason) == "" {
						return agent.ToolResult{
							Text:    "Rejected: reason is required for action=stop.",
							IsError: true,
						}
					}
					if in.Fork != nil {
						return agent.ToolResult{
							Text:    "Rejected: fork cannot be combined with action=stop — a retired worker has no lineage to inherit. Re-issue without fork, or use action=expand to keep this worker alive alongside the fork.",
							IsError: true,
						}
					}
				default:
					return agent.ToolResult{
						Text:    "Rejected: action must be one of continue/expand/stop.",
						IsError: true,
					}
				}
				var fork *ForkSubAction
				if in.Fork != nil {
					if in.Fork.NewWorkerID < 1 {
						return agent.ToolResult{
							Text:    "Rejected: fork.new_worker_id must be >= 1.",
							IsError: true,
						}
					}
					if in.Fork.NewWorkerID == in.WorkerID {
						return agent.ToolResult{
							Text:    "Rejected: fork.new_worker_id must differ from the parent worker_id.",
							IsError: true,
						}
					}
					if strings.TrimSpace(in.Fork.Instruction) == "" {
						return agent.ToolResult{
							Text:    "Rejected: fork.instruction is required.",
							IsError: true,
						}
					}
					if takenIDs != nil {
						taken := takenIDs()
						merged := maps.Clone(taken)
						if merged == nil {
							merged = map[int]bool{}
						}
						// fork IDs claimed earlier in this drain aren't in controller state yet
						maps.Copy(merged, decisions.ForkedIDs())
						if merged[in.Fork.NewWorkerID] {
							return agent.ToolResult{
								Text: fmt.Sprintf(
									"Rejected: fork.new_worker_id=%d collides with an existing, retired, or already-claimed worker. Taken IDs: %s. Pick a fresh integer.",
									in.Fork.NewWorkerID, formatTakenIDs(merged),
								),
								IsError: true,
							}
						}
					}
					fork = &ForkSubAction{
						NewWorkerID: in.Fork.NewWorkerID,
						Instruction: in.Fork.Instruction,
					}
				}
				budget := in.AutonomousBudget
				if budget <= 0 {
					budget = defaultAutonomousBudget
				}
				if budget > maxAutonomousBudget {
					budget = maxAutonomousBudget
				}
				decisions.AddDecision(WorkerDecision{
					Kind:             action,
					WorkerID:         in.WorkerID,
					Instruction:      strings.TrimSpace(in.Instruction),
					Reason:           strings.TrimSpace(in.Reason),
					AutonomousBudget: budget,
					Fork:             fork,
				})
				var note string
				if fork != nil {
					note = fmt.Sprintf(" with fork → worker %d", fork.NewWorkerID)
				}
				return agent.ToolResult{
					Text: fmt.Sprintf(
						"decide_worker recorded: worker %d → %s%s.",
						in.WorkerID, action, note,
					),
				}
			},
		},
	}
}

// SynthesisToolDefs returns the synthesis tool set (plan_workers, direction_done, end_run).
// guardState (required) gates end_run; takenIDs, completedIDs, and aliveWorkerIDs are optional plan/end_run validators.
func SynthesisToolDefs(decisions *DecisionQueue, guardState func() (iter, runFindings int),
	takenIDs TakenIDsFunc, completedIDs func() map[int]bool, aliveWorkerIDs func() []int) []agent.ToolDef {
	reject := func(name string) agent.ToolResult {
		cur := decisions.Phase()
		return agent.ToolResult{
			Text: fmt.Sprintf(
				"Rejected: `%s` is not allowed in phase '%s'. Expected phase 'direction'.",
				name, cur,
			),
			IsError: true,
		}
	}
	return []agent.ToolDef{
		{
			Name: "plan_workers",
			Description: `Spawn fresh workers and/or retarget existing alive workers. ` +
				`Each entry's worker_id must be either an existing alive worker (→ retarget) ` +
				`or an integer NOT in the alive or completed set (→ spawn). ` +
				`Completed worker IDs are gone — picking one is rejected.`,
			Schema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"plans": map[string]any{
						"type": "array",
						"items": map[string]any{
							"type": "object",
							"properties": map[string]any{
								"worker_id":  map[string]any{"type": "integer", "minimum": 1},
								"assignment": map[string]any{"type": "string"},
							},
							"required": []string{"worker_id", "assignment"},
						},
					},
				},
				"required": []string{"plans"},
			},
			Handler: func(ctx context.Context, args json.RawMessage) agent.ToolResult {
				if decisions.Phase() != agent.PhaseDirection {
					return reject("plan_workers")
				}
				var in struct {
					Plans []struct {
						WorkerID   int    `json:"worker_id"`
						Assignment string `json:"assignment"`
					} `json:"plans"`
				}
				if err := unmarshalToolArgs(args, &in); err != nil {
					return agent.ToolResult{
						Text: fmt.Sprintf(
							"Rejected: cannot parse arguments (%s). Expected JSON shape {\"plans\":[{\"worker_id\":N,\"assignment\":\"...\"}]}.",
							err.Error(),
						),
						IsError: true,
					}
				}
				if len(in.Plans) == 0 {
					return agent.ToolResult{
						Text:    "Rejected: 'plans' array is empty. Provide at least one {worker_id, assignment} object.",
						IsError: true,
					}
				}
				var taken map[int]bool
				if takenIDs != nil {
					taken = takenIDs()
				}
				var done map[int]bool
				if completedIDs != nil {
					done = completedIDs()
				}
				var entries []PlanEntry
				var reasons []string
				seen := map[int]bool{}
				for i, p := range in.Plans {
					asg := strings.TrimSpace(p.Assignment)
					if p.WorkerID < 1 {
						reasons = append(reasons, fmt.Sprintf("plans[%d]: worker_id must be >= 1 (got %d)", i, p.WorkerID))
						continue
					}
					if asg == "" {
						reasons = append(reasons, fmt.Sprintf("plans[%d] (worker_id=%d): assignment is empty", i, p.WorkerID))
						continue
					}
					if seen[p.WorkerID] {
						reasons = append(reasons, fmt.Sprintf(
							"plans[%d]: worker_id=%d appears more than once in this plan",
							i, p.WorkerID,
						))
						continue
					}
					seen[p.WorkerID] = true
					// alive: retarget, fresh: spawn, completed: reject
					if done != nil && done[p.WorkerID] {
						reasons = append(reasons, fmt.Sprintf(
							"plans[%d]: worker_id=%d is a retired worker — pick a fresh integer (taken: %s)",
							i, p.WorkerID, formatTakenIDs(taken),
						))
						continue
					}
					entries = append(entries, PlanEntry{WorkerID: p.WorkerID, Assignment: asg})
				}
				if len(entries) == 0 {
					msg := "Rejected: no valid plan entries."
					if len(reasons) > 0 {
						msg += " " + strings.Join(reasons, "; ")
					}
					return agent.ToolResult{Text: msg, IsError: true}
				}
				decisions.SetPlan(entries)
				text := fmt.Sprintf("Plan recorded: %d worker assignment(s).", len(entries))
				if len(reasons) > 0 {
					text += " Skipped: " + strings.Join(reasons, "; ")
				}
				return agent.ToolResult{Text: text}
			},
		},
		{
			Name:        "direction_done",
			Description: `Signal direction phase complete. Use this to close almost every iteration.`,
			Schema: map[string]any{
				"type":       "object",
				"properties": map[string]any{"summary": map[string]any{"type": "string"}},
				"required":   []string{"summary"},
			},
			Handler: func(ctx context.Context, args json.RawMessage) agent.ToolResult {
				if decisions.Phase() != agent.PhaseDirection {
					return reject("direction_done")
				}
				var in struct {
					Summary string `json:"summary"`
				}
				if err := unmarshalToolArgs(args, &in); err != nil {
					return agent.ToolResult{Text: "Rejected: invalid arguments.", IsError: true}
				}
				s := strings.TrimSpace(in.Summary)
				if s == "" {
					return agent.ToolResult{Text: "Rejected: summary is required.", IsError: true}
				}
				decisions.SetDirectionDone(s)
				return agent.ToolResult{Text: "Direction phase complete."}
			},
		},
		{
			Name: "end_run",
			Description: `End the ENTIRE exploration run. Use only after many iterations when ` +
				`the assignment is exhausted and findings have been filed (or the target is confidently clean). ` +
				`Never use this to close a phase — that is direction_done's job.`,
			Schema: map[string]any{
				"type":       "object",
				"properties": map[string]any{"summary": map[string]any{"type": "string"}},
				"required":   []string{"summary"},
			},
			Handler: func(ctx context.Context, args json.RawMessage) agent.ToolResult {
				if decisions.Phase() != agent.PhaseDirection {
					return reject("end_run")
				}
				var in struct {
					Summary string `json:"summary"`
				}
				if err := unmarshalToolArgs(args, &in); err != nil {
					return agent.ToolResult{Text: "Rejected: invalid arguments.", IsError: true}
				}
				s := strings.TrimSpace(in.Summary)
				if s == "" {
					return agent.ToolResult{Text: "Rejected: summary is required.", IsError: true}
				}
				iter, runFindings := guardState()
				if iter < minIterationsForDone && runFindings == 0 {
					return agent.ToolResult{
						Text: fmt.Sprintf(
							"Rejected: `end_run` is premature (iteration %d/%d, %d findings filed this run). "+
								"Use `direction_done(summary)` to close this phase. `end_run` ends the ENTIRE run "+
								"and is only for exhausted assignments after findings have been filed.",
							iter, minIterationsForDone, runFindings,
						),
						IsError: true,
					}
				}
				if aliveWorkerIDs != nil {
					if msg := checkAliveWorkersStopped(aliveWorkerIDs(), decisions.DecisionsByWorker()); msg != "" {
						return agent.ToolResult{Text: msg, IsError: true}
					}
				}
				decisions.SetEndRun(s)
				return agent.ToolResult{Text: "Run end signaled."}
			},
		},
	}
}

// requiredFieldsErr returns a rejection message naming every empty required
// field, or "" when all are present.
func requiredFieldsErr(fields map[string]string) string {
	var missing []string
	for name, val := range fields {
		if strings.TrimSpace(val) == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) == 0 {
		return ""
	}
	sort.Strings(missing)
	return "Rejected: missing required field(s): " + strings.Join(missing, ", ") + "."
}

// pendingCandidateIDs renders the pool's pending candidate IDs for rejection messages.
func pendingCandidateIDs(candidates *CandidatePool) string {
	pending := candidates.Pending()
	ids := make([]string, len(pending))
	for i, c := range pending {
		ids[i] = c.CandidateID
	}
	if len(ids) == 0 {
		return "(none)"
	}
	return strings.Join(ids, ", ")
}

// checkAliveWorkersStopped returns a rejection message naming alive workers whose
// decision this iter is not "stop", or "" when every alive worker has been stopped.
func checkAliveWorkersStopped(alive []int, decisions map[int]string) string {
	var notStopped, noDecision []int
	for _, id := range alive {
		kind, ok := decisions[id]
		if !ok {
			noDecision = append(noDecision, id)
			continue
		}
		if kind != decideActionStop {
			notStopped = append(notStopped, id)
		}
	}
	if len(notStopped) == 0 && len(noDecision) == 0 {
		return ""
	}
	sort.Ints(notStopped)
	sort.Ints(noDecision)
	var parts []string
	if len(notStopped) > 0 {
		parts = append(parts, fmt.Sprintf("workers %v have decisions other than stop this iter", notStopped))
	}
	if len(noDecision) > 0 {
		parts = append(parts, fmt.Sprintf("workers %v have no decision recorded this iter", noDecision))
	}
	return "Rejected: `end_run` would abandon live work — " + strings.Join(parts, "; ") +
		". Either stop them all via decide_worker(action=\"" + decideActionStop + "\", reason=...) " +
		"in this iter and re-issue `end_run`, or call `direction_done(summary)` to close this iter " +
		"and let the workers continue next iter."
}

// formatTakenIDs renders a sorted, comma-separated list of taken IDs, capped at 20.
func formatTakenIDs(taken map[int]bool) string {
	if len(taken) == 0 {
		return "(none)"
	}
	ids := make([]int, 0, len(taken))
	for id := range taken {
		ids = append(ids, id)
	}
	sort.Ints(ids)
	if len(ids) > 20 {
		ids = ids[:20]
	}
	parts := make([]string, len(ids))
	for i, id := range ids {
		parts[i] = strconv.Itoa(id)
	}
	return strings.Join(parts, ", ")
}
