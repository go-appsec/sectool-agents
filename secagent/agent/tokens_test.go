package agent

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCalibration_PerModelIsolation(t *testing.T) {
	// Serial: mutates the model-scoped calibration EMA
	t.Cleanup(resetCalibrationForTest)

	observe := func(model string) {
		h := NewHistoryForModel(8192, model, nil)
		h.Append(Message{Role: RoleUser, Content: "abcdefghij"})
		// raw 11 tokens, reported 200 -> observed ratio clamps the EMA at calibrationMax
		h.SetPromptTokens(200)
	}

	observe("model-a")
	assert.InDelta(t, calibrationMax, Calibration("model-a"), 0.001)
	assert.InDelta(t, 1.0, Calibration("model-b"), 0.001)
	assert.InDelta(t, 1.0, Calibration(""), 0.001)
}

func TestObservePromptTokens_NoopOnNonPositive(t *testing.T) {
	// Serial: guards the model-scoped calibration EMA
	t.Cleanup(resetCalibrationForTest)

	ObservePromptTokens("m", 0, 10)
	ObservePromptTokens("m", 10, 0)
	ObservePromptTokens("m", -1, -1)
	assert.InDelta(t, 1.0, Calibration("m"), 0.001)
}

func TestRawChatMessagesTokens_MatchesStoredShape(t *testing.T) {
	msgs := []Message{
		{Role: RoleSystem, Content: "system prompt"},
		{Role: RoleUser, Content: "hello world hello world"},
		{Role: RoleAssistant, Content: "hi", ToolCalls: []ToolCall{
			{ID: "1", Function: ToolFunction{Name: "tool", Arguments: `{"x":1}`}},
		}},
	}
	chatMsgs := make([]ChatMessage, len(msgs))
	for i, m := range msgs {
		chatMsgs[i] = ChatMessage{
			Role: m.Role, Content: m.Content, ToolCalls: m.ToolCalls, ToolCallID: m.ToolCallID,
		}
	}

	var want int
	for _, m := range msgs {
		want += rawMessageTokens(m)
	}
	assert.Equal(t, want, rawChatMessagesTokens(chatMsgs))
}

func TestRawBodyTokens_ShortToolCallsCounted(t *testing.T) {
	t.Parallel()

	// ten short calls would each truncate to zero under per-call integer division
	calls := make([]ToolCall, 10)
	for i := range calls {
		calls[i] = ToolCall{ID: strconv.Itoa(i), Function: ToolFunction{Name: "t", Arguments: "{}"}}
	}
	m := Message{Role: RoleAssistant, ToolCalls: calls}
	assert.Greater(t, rawMessageTokens(m), perMessageOverhead)

	empty := Message{Role: RoleAssistant}
	assert.Equal(t, perMessageOverhead, rawMessageTokens(empty))
}

func TestEstimateStringTokens_CeilsPartialToken(t *testing.T) {
	t.Parallel()

	assert.Equal(t, 1, EstimateStringTokens("a"))
	assert.Equal(t, 0, EstimateStringTokens(""))
}

func TestEstimateTokensForModel_UsesModelBucket(t *testing.T) {
	// Serial: mutates the model-scoped calibration EMA
	t.Cleanup(resetCalibrationForTest)

	// observed ratio clamps the EMA at calibrationMax
	ObservePromptTokens("model-a", 100, 10)

	s := "abcdefgh"
	assert.Equal(t, EstimateStringTokens(s), EstimateStringTokensForModel("", s))
	assert.Greater(t, EstimateStringTokensForModel("model-a", s), EstimateStringTokensForModel("", s))

	m := Message{Role: RoleUser, Content: s}
	assert.Equal(t, EstimateMessageTokens(m), EstimateMessageTokensForModel("", m))
	assert.Greater(t, EstimateMessageTokensForModel("model-a", m), EstimateMessageTokensForModel("", m))
}
