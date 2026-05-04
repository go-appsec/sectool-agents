package orchestrator

import (
	"context"
	"fmt"
	"slices"

	"github.com/go-appsec/secagent/agent"
	"github.com/go-appsec/secagent/util"
)

// VerificationMaxSubsteps is the hard cap on verifier substeps per iteration.
const VerificationMaxSubsteps = 6

// RunVerificationPhase drives the verifier and returns the summary for the
// director prompt. dedupReviewer may be nil to disable agent-mediated dedup.
func RunVerificationPhase(ctx context.Context, verifier agent.Agent,
	decisions *DecisionQueue, candidates *CandidatePool, writer *FindingWriter,
	dedupReviewer DedupReviewer, log *Logger) string {
	decisions.BeginPhase(agent.PhaseVerification)
	if len(candidates.Pending()) == 0 {
		log.Log("verify", "no pending candidates; skipping", nil)
		return "No pending candidates this iteration."
	}
	var appliedFindings, appliedDismissals int
	for substep := 1; substep <= VerificationMaxSubsteps; substep++ {
		pending := candidates.Pending()
		if len(pending) == 0 {
			break
		}
		// substep 1 directive was installed by the controller
		if substep > 1 {
			prompt := BuildVerifierContinuePrompt(
				pending,
				decisions.Findings[:appliedFindings],
				decisions.Dismissals[:appliedDismissals],
				substep, VerificationMaxSubsteps,
			)
			verifier.Query(prompt)
		}
		_, err := RunPhaseAttempt(ctx,
			func(c context.Context) (agent.TurnSummary, error) { return verifier.Drain(c) },
			PhaseRecover{
				Compact: func() {
					verifier.Interrupt()
					// substep 1 directive is the installed compose; substeps 2..N requeue the continue
					if substep > 1 {
						verifier.Query(BuildVerifierContinuePrompt(
							pending,
							decisions.Findings[:appliedFindings],
							decisions.Dismissals[:appliedDismissals],
							substep, VerificationMaxSubsteps,
						))
					}
				},
				OnExhausted: func(err error) {
					// pending candidates carry to next iter for a fresh-compose retry
				},
			}, log, "verify")
		if err != nil {
			break
		}
		// dedup pipeline: skip exact same-title/same-endpoint repeats this substep
		seenFindings := map[string]bool{}
		for _, filed := range decisions.Findings[appliedFindings:] {
			titleKey := util.Slugify(filed.Title)
			if titleKey == "" {
				titleKey = filed.Title
			}
			key := titleKey + "|" + CanonicalEndpoint(filed.Endpoint)
			if seenFindings[key] {
				continue
			}
			seenFindings[key] = true
			wrote, path, err := ReviewAndWrite(ctx, dedupReviewer, writer, filed, log)
			if err != nil {
				log.Log("finding", "write failed", map[string]any{"err": err.Error()})
				continue
			} else if wrote {
				log.Log("finding", "written", map[string]any{"path": path, "title": filed.Title})
			}
			resolved := slices.Clone(filed.SupersedesCandidateIDs)
			matchTier := MatchNone
			pendingNow := candidates.Pending()
			if len(resolved) == 0 {
				resolved, matchTier = MatchPendingCandidatesTiered(filed, pendingNow)
			}
			for _, cid := range resolved {
				candidates.Mark(cid, CandidateStatusVerified)
			}
			switch {
			case len(filed.SupersedesCandidateIDs) > 0:
				// explicit link, nothing to flag
			case matchTier != MatchNone && matchTier != MatchTitleAndEndpoint:
				// looser tier matched, surface diverging titles/endpoints
				log.Log("finding", "candidate match-fallback", map[string]any{
					"tier":     matchTier.String(),
					"title":    filed.Title,
					"endpoint": filed.Endpoint,
					"resolved": resolved,
				})
			case len(resolved) == 0 && len(pendingNow) > 0:
				// orphan: written but no candidate resolved, would loop forever
				pendingIDs := make([]string, len(pendingNow))
				for i, c := range pendingNow {
					pendingIDs[i] = c.CandidateID
				}
				log.Log("finding", "orphan — no pending candidate matched", map[string]any{
					"title":    filed.Title,
					"endpoint": filed.Endpoint,
					"pending":  pendingIDs,
				})
			}
		}
		appliedFindings = len(decisions.Findings)

		// log only on state transition so repeat dismiss calls don't spam
		for _, dm := range decisions.Dismissals[appliedDismissals:] {
			c := candidates.ByID(dm.CandidateID)
			if c == nil || c.Status != CandidateStatusPending {
				continue
			}
			candidates.Mark(dm.CandidateID, CandidateStatusDismissed)
			log.Log("finding", "candidate dismissed", map[string]any{"candidate_id": dm.CandidateID})
		}
		appliedDismissals = len(decisions.Dismissals)

		if decisions.HasVerificationDone {
			break
		}
	}

	if decisions.HasVerificationDone && decisions.VerificationDoneSummary != "" {
		return decisions.VerificationDoneSummary
	}
	return fmt.Sprintf(
		"Verification phase ended with %d filed, %d dismissed, %d still pending.",
		appliedFindings, appliedDismissals, len(candidates.Pending()),
	)
}

// AutoDismissOnContextOverflow marks every pending candidate as dismissed with a
// "context budget exhausted" reason and records each dismissal on the decision queue.
func AutoDismissOnContextOverflow(
	candidates *CandidatePool,
	decisions *DecisionQueue,
	log *Logger,
) {
	pending := candidates.Pending()
	for _, c := range pending {
		candidates.Mark(c.CandidateID, CandidateStatusDismissed)
		decisions.AddDismissal(CandidateDismissal{
			CandidateID: c.CandidateID,
			Reason:      "auto: verifier context budget exhausted after fresh compose",
		})
		log.Log("verify", "auto-dismiss on context-budget overflow", map[string]any{
			"candidate_id": c.CandidateID,
		})
	}
}
