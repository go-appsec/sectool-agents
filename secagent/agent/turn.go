package agent

// ClassifyEscalation returns the escalation reason for s, or "" when the turn was productive.
// candidateFound signals that this turn produced a new candidate. A pre-set EscalationReason on s is preserved as-is.
func ClassifyEscalation(s TurnSummary, candidateFound bool) string {
	if s.EscalationReason == escalationContextExhausted {
		return escalationContextExhausted
	} else if s.TimedOut {
		return escalationSilent
	} else if candidateFound {
		return escalationCandidate
	} else if len(s.ToolCalls) == 0 && len(s.FlowIDs) == 0 {
		return escalationSilent
	}
	return ""
}
