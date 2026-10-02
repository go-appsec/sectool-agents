package agent

import "sync"

// Tunables for the learned token calibration. The estimator multiplies a raw char/charsPerToken count by a
// calibration factor updated by EMA on each observed prompt-token count. Bounds prevent outliers. Calibration
// is scoped per model so different tokenizers cannot contaminate each other's estimates.
const (
	charsPerToken      = 4
	perMessageOverhead = 4
	calibrationMin     = 0.5
	calibrationMax     = 3.0
	calibrationAlpha   = 0.3
)

var (
	calibrationMu      sync.RWMutex
	calibrationByModel = map[string]float64{}
)

// Calibration returns the learned multiplier applied to char/N estimates for model.
// Unobserved models default to 1.0.
func Calibration(model string) float64 {
	calibrationMu.RLock()
	defer calibrationMu.RUnlock()
	return calibrationForLocked(model)
}

// ObservePromptTokens updates the model-scoped calibration EMA from one (real, raw) observation.
// real is the server-reported prompt token count, raw the matching uncalibrated estimate over the
// same message shape. No-op when either is non-positive.
func ObservePromptTokens(model string, real, raw int) {
	if real <= 0 || raw <= 0 {
		return
	}
	observed := float64(real) / float64(raw)
	calibrationMu.Lock()
	defer calibrationMu.Unlock()
	next := (1-calibrationAlpha)*calibrationForLocked(model) + calibrationAlpha*observed
	if next < calibrationMin {
		next = calibrationMin
	} else if next > calibrationMax {
		next = calibrationMax
	}
	calibrationByModel[model] = next
}

// calibrationForLocked returns the stored factor for model, seeded at 1.0.
func calibrationForLocked(model string) float64 {
	if c, ok := calibrationByModel[model]; ok {
		return c
	}
	return 1.0
}

// resetCalibrationForTest restores every model's calibration to its 1.0 seed.
func resetCalibrationForTest() {
	calibrationMu.Lock()
	calibrationByModel = map[string]float64{}
	calibrationMu.Unlock()
}

// EstimateStringTokens returns the token estimate for s using the default calibration bucket, with
// no per-message overhead. Model-scoped estimation goes through History or EstimateStringTokensForModel.
func EstimateStringTokens(s string) int {
	return EstimateStringTokensForModel("", s)
}

// EstimateStringTokensForModel returns the token estimate for s using model's calibration bucket,
// with no per-message overhead.
func EstimateStringTokensForModel(model, s string) int {
	return int(float64(len(s)) / charsPerToken * Calibration(model))
}

// EstimateMessageTokens returns the token estimate for m using the default calibration bucket,
// including per-message overhead. Model-scoped estimation goes through History or
// EstimateMessageTokensForModel.
func EstimateMessageTokens(m Message) int {
	return EstimateMessageTokensForModel("", m)
}

// EstimateMessageTokensForModel returns the token estimate for m using model's calibration bucket,
// including per-message overhead.
func EstimateMessageTokensForModel(model string, m Message) int {
	return int(float64(rawMessageTokens(m)) * Calibration(model))
}

// rawMessageTokens returns the uncalibrated token estimate for m, including per-message overhead.
// ReasoningContent is excluded since it never reaches the wire.
func rawMessageTokens(m Message) int {
	return rawBodyTokens(m.Content, m.ToolCalls)
}

// rawChatMessagesTokens returns the uncalibrated token estimate for the message shape sent on the
// wire, including per-message overhead.
func rawChatMessagesTokens(msgs []ChatMessage) int {
	var total int
	for _, m := range msgs {
		total += rawBodyTokens(m.Content, m.ToolCalls)
	}
	return total
}

// rawBodyTokens returns the uncalibrated estimate for one message body, including per-message overhead.
func rawBodyTokens(content string, calls []ToolCall) int {
	total := len(content) / charsPerToken
	for _, tc := range calls {
		total += (len(tc.Function.Name) + len(tc.Function.Arguments)) / charsPerToken
	}
	return total + perMessageOverhead
}
