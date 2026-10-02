package orchestrator

import (
	"context"
	"fmt"
	"slices"

	"github.com/go-appsec/sectool-agents/secagent/agent"
	"github.com/go-appsec/sectool-agents/secagent/util"
)

// VerificationMaxSubsteps is the hard cap on verifier substeps per iteration.
const VerificationMaxSubsteps = 6

// verificationIdleRetries bounds consecutive no-op verifier drains; idle
// re-prompts don't consume the VerificationMaxSubsteps cap.
const verificationIdleRetries = 3

// RunVerificationPhase drives the verifier and returns the summary for the
// director prompt. dedupReviewer may be nil to disable agent-mediated dedup.
// Findings recorded before a failed substep drain are still written. Idle
// drains (no tool calls, no decisions) are re-prompted without consuming
// the substep cap, bounded by verificationIdleRetries.
func RunVerificationPhase(ctx context.Context, verifier agent.Agent,
	decisions *DecisionQueue, candidates *CandidatePool, writer *FindingWriter,
	dedupReviewer DedupReviewer, log *Logger) string {
	decisions.BeginPhase(agent.PhaseVerification)
	if len(candidates.Pending()) == 0 {
		log.Log("verify", "no pending candidates; skipping", nil)
		return "No pending candidates this iteration."
	}
	var appliedFindings, appliedDismissals, filedCount, dismissedCount int
	idleStreak := 0
	for substep := 1; substep <= VerificationMaxSubsteps; {
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
			if idleStreak > 0 {
				prompt += "\n\n" + BuildVerifierIdleRetryPrompt(verificationIdleRetries-idleStreak)
			}
			verifier.Query(prompt)
		} else if idleStreak > 0 {
			// initial compose is already installed; nudge only
			verifier.Query(BuildVerifierIdleRetryPrompt(verificationIdleRetries - idleStreak))
		}
		decisionsBefore := len(decisions.Findings) + len(decisions.Dismissals)
		turn, drainErr := RunPhaseAttempt(ctx,
			func(c context.Context) (agent.TurnSummary, error) { return verifier.Drain(c) },
			PhaseRecover{
				Compact: func() {
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
		// apply decisions even after a failed drain so recorded work isn't dropped
		seenFindings := map[string]bool{}
		for _, filed := range decisions.Findings[appliedFindings:] {
			titleKey := util.Slugify(filed.Title)
			if titleKey == "" {
				titleKey = filed.Title
			}
			key := titleKey + "|" + CanonicalEndpoint(filed.Endpoint)
			if seenFindings[key] {
				// duplicate within the substep: skip the write but still honor explicit links
				for _, cid := range filed.SupersedesCandidateIDs {
					candidates.Mark(cid, CandidateStatusVerified)
				}
				continue
			}
			seenFindings[key] = true
			wrote, path, err := ReviewAndWrite(ctx, dedupReviewer, writer, filed, log)
			if err != nil {
				log.Log("finding", "write failed", map[string]any{"err": err.Error()})
				continue
			} else if wrote {
				filedCount++
				log.Log("finding", "written", map[string]any{"path": path, "title": filed.Title})
			}
			resolved := slices.Clone(filed.SupersedesCandidateIDs)
			pendingNow := candidates.Pending()
			var tierMatched []string
			matchTier := MatchNone
			if len(resolved) == 0 {
				tierMatched, matchTier = MatchPendingCandidatesTiered(filed, pendingNow)
				// only title+endpoint resolves implicitly; looser tiers stay
				// pending for an explicit verdict
				if matchTier.Terminal() {
					resolved = tierMatched
				}
			}
			for _, cid := range resolved {
				candidates.Mark(cid, CandidateStatusVerified)
			}
			switch {
			case len(filed.SupersedesCandidateIDs) > 0, matchTier == MatchTitleAndEndpoint:
				// explicit or unambiguous link, nothing to flag
			case matchTier != MatchNone:
				// loose tier hit: too ambiguous to resolve, left pending
				log.Log("finding", "candidate match-fallback", map[string]any{
					"tier":     matchTier.String(),
					"title":    filed.Title,
					"endpoint": filed.Endpoint,
					"matched":  tierMatched,
					"titles":   candidateTitles(tierMatched, pendingNow),
				})
			case len(pendingNow) > 0:
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
			dismissedCount++
			log.Log("finding", "candidate dismissed", map[string]any{"candidate_id": dm.CandidateID})
		}
		appliedDismissals = len(decisions.Dismissals)

		if drainErr != nil {
			break
		}
		if decisions.HasVerificationDone {
			break
		}
		// only substeps that changed observable state consume the cap
		if verificationSubstepProductive(turn, decisions,
			decisionsBefore, len(pending), len(candidates.Pending())) {
			idleStreak = 0
			substep++
			continue
		}
		// idle drain: re-prompt without advancing the substep
		idleStreak++
		log.Log("verify", "idle verifier drain", map[string]any{
			"substep": substep, "idle_streak": idleStreak,
		})
		if idleStreak >= verificationIdleRetries {
			log.Log("verify", "idle drain limit reached", map[string]any{
				"pending": len(candidates.Pending()),
			})
			break
		}
	}

	if decisions.HasVerificationDone && decisions.VerificationDoneSummary != "" {
		return decisions.VerificationDoneSummary
	}
	// counts reflect applied outcomes, not queue entries, so duplicate
	// filings and repeat dismissals don't inflate the director prompt
	return fmt.Sprintf(
		"Verification phase ended with %d filed, %d dismissed, %d still pending.",
		filedCount, dismissedCount, len(candidates.Pending()),
	)
}

// verificationSubstepProductive reports whether a verifier drain changed
// observable state and should consume the substep cap.
func verificationSubstepProductive(turn agent.TurnSummary, decisions *DecisionQueue,
	decisionsBefore, pendingBefore, pendingAfter int) bool {
	decisionsAfter := len(decisions.Findings) + len(decisions.Dismissals)
	return len(turn.ToolCalls) > 0 || decisionsAfter > decisionsBefore ||
		pendingAfter != pendingBefore
}

// candidateTitles maps matched candidate IDs to their titles for audit logs.
func candidateTitles(ids []string, pending []FindingCandidate) map[string]string {
	titles := make(map[string]string, len(ids))
	for _, c := range pending {
		if slices.Contains(ids, c.CandidateID) {
			titles[c.CandidateID] = c.Title
		}
	}
	return titles
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
