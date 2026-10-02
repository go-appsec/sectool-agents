package agent

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCalibration_PerModelIsolation(t *testing.T) {
	// Serial: mutates the model-scoped calibration EMA
	t.Cleanup(resetCalibrationForTest)

	observe := func(model string) {
		h := NewHistoryForModel(8192, model, nil)
		h.Append(Message{Role: RoleUser, Content: "abcdefghij"})
		// raw 6 tokens, reported 60 -> observed ratio clamps the EMA at calibrationMax
		h.SetPromptTokens(60)
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
