package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/go-appsec/secagent/agent"
	"github.com/go-appsec/secagent/history"
	"github.com/go-appsec/secagent/util"
)

// Dedup verdict actions. Pair-wise (DedupVerdict) uses unique / duplicate / partial;
// multi-existing (CandidateDedupVerdict) uses unique / duplicate / merge.
const (
	dedupActionUnique    = "unique"
	dedupActionDuplicate = "duplicate"
	dedupActionPartial   = "partial"
	dedupActionMerge     = "merge"
)

// DedupVerdict classifies the relationship between two findings.
// MoreComplete is "existing" or "new" for "duplicate" and "partial".
type DedupVerdict struct {
	Action       string // "unique" | "duplicate" | "partial"
	MoreComplete string // "existing" | "new"
}

// DedupReviewer classifies and merges pair-wise findings.
type DedupReviewer interface {
	Classify(ctx context.Context, existing, incoming FindingFiled) (DedupVerdict, error)
	Merge(ctx context.Context, primary, secondary FindingFiled) (FindingFiled, error)
}

// OpenAIDedupReviewer classifies and merges findings via one-shot OpenAI-compatible chat completions.
type OpenAIDedupReviewer struct {
	Pool      *agent.ClientPool
	Model     string
	MaxTokens int
	Log       *Logger
}

// Classify returns the model's verdict comparing existing to incoming.
func (r *OpenAIDedupReviewer) Classify(ctx context.Context, existing, incoming FindingFiled) (DedupVerdict, error) {
	prompt := classifyPrompt(existing, incoming)
	raw, err := r.oneShot(ctx, dedupSystemPrompt, prompt)
	if err != nil {
		return DedupVerdict{}, fmt.Errorf("dedup classify: %w", err)
	}
	return parseVerdict(raw)
}

// CandidateDedupVerdict is the disposition of one incoming candidate.
// MatchedFilename and Reason are populated for "duplicate" and "merge".
type CandidateDedupVerdict struct {
	Action          string // "unique" | "duplicate" | "merge"
	MatchedFilename string
	Reason          string
}

// CandidateDedupReviewer classifies one candidate against existing digests.
type CandidateDedupReviewer interface {
	ClassifyCandidate(ctx context.Context, incoming AddInput, digests []FindingDigest) (CandidateDedupVerdict, error)
}

// ClassifyCandidate returns the verdict for incoming compared to digests.
// An empty digests slice yields a unique verdict without calling the model.
func (r *OpenAIDedupReviewer) ClassifyCandidate(ctx context.Context, incoming AddInput, digests []FindingDigest) (CandidateDedupVerdict, error) {
	if len(digests) == 0 {
		return CandidateDedupVerdict{Action: dedupActionUnique}, nil
	}
	prompt := candidateClassifyPrompt(incoming, digests)
	raw, err := r.oneShot(ctx, dedupSystemPrompt, prompt)
	if err != nil {
		return CandidateDedupVerdict{}, fmt.Errorf("dedup classify candidate: %w", err)
	}
	return parseCandidateVerdict(raw, digests)
}

// Merge returns one finding coalescing primary (the more-complete side) with unique details from secondary.
func (r *OpenAIDedupReviewer) Merge(ctx context.Context, primary, secondary FindingFiled) (FindingFiled, error) {
	prompt := mergePrompt(primary, secondary)
	raw, err := r.oneShot(ctx, dedupSystemPrompt, prompt)
	if err != nil {
		return FindingFiled{}, fmt.Errorf("dedup merge: %w", err)
	}
	return parseMerge(raw, primary)
}

// oneShot runs one classify/merge chat completion and returns the trimmed response.
func (r *OpenAIDedupReviewer) oneShot(ctx context.Context, system, user string) (string, error) {
	maxTokens := r.MaxTokens
	if maxTokens <= 0 {
		maxTokens = 20000
	}
	return history.RunOneShot(ctx, r.Pool, r.Model, system, user, maxTokens, agent.CompressionReasoningEffort, nil)
}

const dedupSystemPrompt = `You review security findings for duplication. Respond with JSON only — no prose, no markdown fences. Your output must parse as a single JSON object.`

func classifyPrompt(existing, incoming FindingFiled) string {
	var b strings.Builder
	b.WriteString("Compare two security findings. Decide whether they describe the same vulnerability.\n\n")
	b.WriteString("## Existing finding (already written to disk)\n")
	writeFindingBlock(&b, existing)
	b.WriteString("\n## New finding (just reported)\n")
	writeFindingBlock(&b, incoming)
	b.WriteString(`
## Response

Respond with exactly one JSON object:

  {"action": "unique"}
  {"action": "duplicate", "more_complete": "existing"}
  {"action": "duplicate", "more_complete": "new"}
  {"action": "partial", "more_complete": "existing"}
  {"action": "partial", "more_complete": "new"}

Meaning:
- "unique": different vulnerabilities that happen to share words; keep both.
- "duplicate": same vulnerability; pick which write-up is more thorough.
- "partial": same vulnerability class but each has unique details worth merging; pick which is the stronger base.

Return only the JSON object. No explanation.
`)
	return b.String()
}

func mergePrompt(primary, secondary FindingFiled) string {
	var b strings.Builder
	b.WriteString("Merge two security findings that describe the same vulnerability. Keep the primary's structure and voice; fold in unique details from the secondary. Do not drop reproduction steps or evidence from either side.\n\n")
	b.WriteString("## Primary (base to keep)\n")
	writeFindingBlock(&b, primary)
	b.WriteString("\n## Secondary (fold in unique details)\n")
	writeFindingBlock(&b, secondary)
	b.WriteString(`
## Response

Respond with a single JSON object containing the merged finding:

  {
    "title": "...",
    "severity": "low|medium|high|critical",
    "endpoint": "METHOD /path",
    "description": "...",
    "reproduction_steps": "...",
    "evidence": "...",
    "impact": "...",
    "verification_notes": "..."
  }

Return only the JSON object. No explanation.
`)
	return b.String()
}

// candidateClassifyPrompt renders the candidate-vs-digests classify request.
func candidateClassifyPrompt(incoming AddInput, digests []FindingDigest) string {
	var b strings.Builder
	b.WriteString("A worker reported a candidate security finding. Decide whether it is genuinely new or already covered by an existing finding.\n\n")
	b.WriteString("## Existing findings\n\n")
	for i, d := range digests {
		_, _ = fmt.Fprintf(&b, "[%d] file: %s\n", i+1, d.Filename)
		_, _ = fmt.Fprintf(&b, "    title: %s\n", d.Title)
		_, _ = fmt.Fprintf(&b, "    severity: %s\n", d.Severity)
		_, _ = fmt.Fprintf(&b, "    endpoint: %s\n", d.Endpoint)
		if d.FirstLines != "" {
			_, _ = fmt.Fprintf(&b, "    excerpt:\n      %s\n", strings.ReplaceAll(d.FirstLines, "\n", "\n      "))
		}
		b.WriteString("\n")
	}
	b.WriteString("## New candidate\n\n")
	_, _ = fmt.Fprintf(&b, "Title: %s\n", incoming.Title)
	_, _ = fmt.Fprintf(&b, "Severity: %s\n", incoming.Severity)
	_, _ = fmt.Fprintf(&b, "Endpoint: %s\n", incoming.Endpoint)
	_, _ = fmt.Fprintf(&b, "Summary: %s\n", orDefault(incoming.Summary, noneSentinel))
	_, _ = fmt.Fprintf(&b, "Evidence notes: %s\n", orDefault(incoming.EvidenceNotes, noneSentinel))
	_, _ = fmt.Fprintf(&b, "Reproduction hint: %s\n", orDefault(incoming.ReproductionHint, noneSentinel))
	b.WriteString(`
## Response

Respond with exactly one JSON object:

  {"action": "unique"}
  {"action": "duplicate", "matched_filename": "finding-NN-...md", "reason": "short reason"}
  {"action": "merge", "matched_filename": "finding-NN-...md", "reason": "short reason"}

Meaning:
- "unique": this candidate describes a vulnerability not covered by any existing finding.
- "duplicate": an existing finding already covers this candidate fully — nothing new to add.
- "merge": same vulnerability as an existing finding, but the candidate has unique evidence or details worth folding in.

Return only the JSON object. No prose, no markdown fences.
`)
	return b.String()
}

func parseCandidateVerdict(raw string, digests []FindingDigest) (CandidateDedupVerdict, error) {
	body := util.ExtractJSONObject(raw)
	var v struct {
		Action          string `json:"action"`
		MatchedFilename string `json:"matched_filename"`
		Reason          string `json:"reason"`
	}
	if err := json.Unmarshal([]byte(body), &v); err != nil {
		return CandidateDedupVerdict{}, fmt.Errorf("parse candidate verdict: %w (raw: %q)", err, raw)
	}
	switch v.Action {
	case dedupActionUnique:
		return CandidateDedupVerdict{Action: dedupActionUnique}, nil
	case dedupActionDuplicate, dedupActionMerge:
		if v.MatchedFilename == "" {
			return CandidateDedupVerdict{}, fmt.Errorf("verdict %q missing matched_filename (raw: %q)", v.Action, raw)
		}
		known := slices.ContainsFunc(digests, func(d FindingDigest) bool {
			return d.Filename == v.MatchedFilename
		})
		if !known {
			return CandidateDedupVerdict{}, fmt.Errorf("verdict references unknown filename %q (raw: %q)", v.MatchedFilename, raw)
		}
		return CandidateDedupVerdict{
			Action:          v.Action,
			MatchedFilename: v.MatchedFilename,
			Reason:          v.Reason,
		}, nil
	default:
		return CandidateDedupVerdict{}, fmt.Errorf("unknown action %q (raw: %q)", v.Action, raw)
	}
}

func writeFindingBlock(b *strings.Builder, f FindingFiled) {
	_, _ = fmt.Fprintf(b, "Title: %s\n", f.Title)
	_, _ = fmt.Fprintf(b, "Severity: %s\n", f.Severity)
	_, _ = fmt.Fprintf(b, "Endpoint: %s\n", f.Endpoint)
	_, _ = fmt.Fprintf(b, "\nDescription:\n%s\n", orDefault(f.Description, noneSentinel))
	_, _ = fmt.Fprintf(b, "\nReproduction:\n%s\n", orDefault(f.ReproductionSteps, noneSentinel))
	_, _ = fmt.Fprintf(b, "\nEvidence:\n%s\n", orDefault(f.Evidence, noneSentinel))
	_, _ = fmt.Fprintf(b, "\nImpact:\n%s\n", orDefault(f.Impact, noneSentinel))
	_, _ = fmt.Fprintf(b, "\nVerification:\n%s\n", orDefault(f.VerificationNotes, noneSentinel))
}

func parseVerdict(raw string) (DedupVerdict, error) {
	body := util.ExtractJSONObject(raw)
	var v struct {
		Action       string `json:"action"`
		MoreComplete string `json:"more_complete"`
	}
	if err := json.Unmarshal([]byte(body), &v); err != nil {
		return DedupVerdict{}, fmt.Errorf("parse verdict: %w (raw: %q)", err, raw)
	}
	switch v.Action {
	case dedupActionUnique:
		return DedupVerdict{Action: dedupActionUnique}, nil
	case dedupActionDuplicate, dedupActionPartial:
		if v.MoreComplete != "existing" && v.MoreComplete != "new" {
			return DedupVerdict{}, fmt.Errorf("verdict %q missing more_complete in/out (raw: %q)", v.Action, raw)
		}
		return DedupVerdict{Action: v.Action, MoreComplete: v.MoreComplete}, nil
	default:
		return DedupVerdict{}, fmt.Errorf("unknown action %q (raw: %q)", v.Action, raw)
	}
}

func parseMerge(raw string, fallback FindingFiled) (FindingFiled, error) {
	body := util.ExtractJSONObject(raw)
	var m struct {
		Title             string `json:"title"`
		Severity          string `json:"severity"`
		Endpoint          string `json:"endpoint"`
		Description       string `json:"description"`
		ReproductionSteps string `json:"reproduction_steps"`
		Evidence          string `json:"evidence"`
		Impact            string `json:"impact"`
		VerificationNotes string `json:"verification_notes"`
	}
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		return FindingFiled{}, fmt.Errorf("parse merge: %w (raw: %q)", err, raw)
	}
	out := fallback // preserve SupersedesCandidateIDs / FollowUpHint from primary
	if m.Title != "" {
		out.Title = m.Title
	}
	if m.Severity != "" {
		out.Severity = m.Severity
	}
	if m.Endpoint != "" {
		out.Endpoint = m.Endpoint
	}
	if m.Description != "" {
		out.Description = m.Description
	}
	if m.ReproductionSteps != "" {
		out.ReproductionSteps = m.ReproductionSteps
	}
	if m.Evidence != "" {
		out.Evidence = m.Evidence
	}
	if m.Impact != "" {
		out.Impact = m.Impact
	}
	if m.VerificationNotes != "" {
		out.VerificationNotes = m.VerificationNotes
	}
	return out, nil
}

// ReviewAndWrite persists incoming after dedup. Returns (wrote, path, err) where wrote
// is true when a new file was persisted, and path is "" only when incoming is an exact duplicate.
func ReviewAndWrite(ctx context.Context,
	reviewer DedupReviewer, writer *FindingWriter, incoming FindingFiled, log *Logger) (bool, string, error) {
	if writer.IsDuplicate(incoming) {
		log.Log("finding", "duplicate skipped", map[string]any{"title": incoming.Title})
		return false, "", nil
	}
	similars := writer.FindSimilarEntries(incoming)
	if len(similars) == 0 || reviewer == nil {
		path, err := writer.Write(incoming)
		return err == nil, path, err
	}
	for _, s := range similars {
		verdict, err := reviewer.Classify(ctx, s.Filed, incoming)
		if err != nil {
			log.Log("finding", "dedup classify error", map[string]any{
				"err": err.Error(), "similar": s.Path,
			})
			continue
		} else if verdict.Action == "unique" {
			continue
		}
		return ApplyDedupVerdict(ctx, reviewer, writer, incoming, s, verdict, log)
	}
	path, err := writer.Write(incoming)
	return err == nil, path, err
}

// ApplyDedupVerdict routes verdict to the matching writer action. Returns (wrote, resolvedPath, err);
// wrote is true only when a new finding file was persisted.
func ApplyDedupVerdict(ctx context.Context,
	reviewer DedupReviewer, writer *FindingWriter, incoming FindingFiled, similar SimilarFinding,
	verdict DedupVerdict, log *Logger) (wrote bool, resolvedPath string, err error) {
	switch verdict.Action {
	case dedupActionUnique:
		path, werr := writer.Write(incoming)
		if werr != nil {
			return false, "", werr
		}
		log.Log("finding", "dedup-unique", map[string]any{"path": path, "similar_to": similar.Path})
		return true, path, nil

	case dedupActionDuplicate:
		if verdict.MoreComplete == "new" {
			// replace existing file's content with incoming, keep its sequence
			newPath, rerr := writer.Replace(similar.Path, incoming)
			if rerr != nil {
				return false, "", rerr
			}
			log.Log("finding", "dedup-duplicate-replace", map[string]any{
				"path": newPath, "replaced": similar.Path,
			})
			return false, newPath, nil
		}
		// keep existing, discard incoming
		log.Log("finding", "dedup-duplicate-skip", map[string]any{
			"kept": similar.Path, "discarded_title": incoming.Title,
		})
		return false, similar.Path, nil

	case dedupActionPartial:
		primary, secondary := similar.Filed, incoming
		if verdict.MoreComplete == "new" {
			primary, secondary = incoming, similar.Filed
		}
		merged, merr := reviewer.Merge(ctx, primary, secondary)
		if merr != nil {
			return false, "", merr
		}
		newPath, rerr := writer.Replace(similar.Path, merged)
		if rerr != nil {
			return false, "", rerr
		}
		log.Log("finding", "dedup-partial-merge", map[string]any{
			"path": newPath, "merged_into": similar.Path, "more_complete": verdict.MoreComplete,
		})
		return false, newPath, nil

	default:
		return false, "", fmt.Errorf("apply dedup: unknown action %q", verdict.Action)
	}
}
