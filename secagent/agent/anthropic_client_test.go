package agent

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDetectChatFormat(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		baseURL  string
		model    string
		force    bool
		expected ChatFormat
	}{
		{"default endpoint openai", "", "gpt-5", false, ChatFormatOpenAI},
		{"default endpoint claude", "", "claude-sonnet-4", false, ChatFormatAnthropic},
		{"anthropic base url", "https://api.anthropic.com", "claude-sonnet-4", false, ChatFormatAnthropic},
		{"proxy keeps openai", "https://openrouter.ai/api/v1", "anthropic/claude-sonnet-4", false, ChatFormatOpenAI},
		{"gateway keeps openai", "http://127.0.0.1:8000/v1", "claude-sonnet-4", false, ChatFormatOpenAI},
		{"force wins over proxy", "https://openrouter.ai/api/v1", "gpt-5", true, ChatFormatAnthropic},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := DetectChatFormat(tc.baseURL, tc.model, tc.force)
			assert.Equal(t, tc.expected, got)
		})
	}
}

func TestBuildAnthropicRequest(t *testing.T) {
	t.Parallel()

	req := ChatRequest{
		Model:     "claude-sonnet-4",
		MaxTokens: 0,
		Messages: []ChatMessage{
			{Role: RoleSystem, Content: "you are a tester"},
			{Role: RoleUser, Content: "find bugs"},
			{Role: RoleAssistant, Content: "on it", ToolCalls: []ToolCall{
				{ID: "tc1", Type: "function", Function: ToolFunction{Name: "scan", Arguments: `{"url":"http://x"}`}},
			}},
			{Role: RoleTool, ToolCallID: "tc1", Content: "no findings"},
			{Role: RoleTool, ToolCallID: "tc2", Content: "also clean"},
			{Role: RoleUser, Content: "go deeper"},
		},
		Tools: []ChatTool{{
			Type: "function",
			Function: ChatToolSchema{Name: "scan", Description: "scan a url",
				Parameters: map[string]any{"type": "object"}},
		}},
	}

	out, err := buildAnthropicRequest(req, 8192)
	require.NoError(t, err)

	assert.Equal(t, "claude-sonnet-4", out.Model)
	assert.Equal(t, 8192, out.MaxTokens)
	require.Len(t, out.System, 1)
	assert.Equal(t, "you are a tester", out.System[0].Text)

	// system lifts out; assistant tool round-trip then consecutive tool
	// results merge into a single user message before the final user turn
	require.Len(t, out.Messages, 3)
	assert.Equal(t, RoleUser, out.Messages[0].Role)
	assert.Equal(t, RoleAssistant, out.Messages[1].Role)
	require.Len(t, out.Messages[1].Content, 2)
	assert.Equal(t, "text", out.Messages[1].Content[0].Type)
	assert.Equal(t, "tool_use", out.Messages[1].Content[1].Type)
	assert.Equal(t, "tc1", out.Messages[1].Content[1].ID)
	assert.Equal(t, "scan", out.Messages[1].Content[1].Name)
	assert.JSONEq(t, `{"url":"http://x"}`, string(out.Messages[1].Content[1].Input))

	require.Len(t, out.Messages[2].Content, 3) // two tool_result + trailing user text
	assert.Equal(t, "tool_result", out.Messages[2].Content[0].Type)
	assert.Equal(t, "tc1", out.Messages[2].Content[0].ToolUseID)
	assert.Equal(t, "tool_result", out.Messages[2].Content[1].Type)
	assert.Equal(t, "tc2", out.Messages[2].Content[1].ToolUseID)
	assert.Equal(t, "text", out.Messages[2].Content[2].Type)
	assert.Equal(t, "go deeper", out.Messages[2].Content[2].Text)

	require.Len(t, out.Tools, 1)
	assert.Equal(t, "scan", out.Tools[0].Name)
	assert.JSONEq(t, `{"type":"object"}`, string(out.Tools[0].InputSchema))
}

func TestBuildAnthropicRequestMaxTokensOverride(t *testing.T) {
	t.Parallel()

	req := ChatRequest{Model: "claude-sonnet-4", MaxTokens: 512,
		Messages: []ChatMessage{{Role: RoleUser, Content: "hi"}}}
	out, err := buildAnthropicRequest(req, 8192)
	require.NoError(t, err)
	assert.Equal(t, 512, out.MaxTokens)
}

func TestBuildAnthropicRequestDefaults(t *testing.T) {
	t.Parallel()

	// empty tool args become {}, invalid args are wrapped so the wire stays valid,
	// empty content is padded, and a message with neither text nor calls is dropped
	req := ChatRequest{Model: "claude-sonnet-4",
		Messages: []ChatMessage{
			{Role: RoleUser, Content: ""},
			{Role: RoleAssistant, Content: ""},
			{Role: RoleAssistant, ToolCalls: []ToolCall{
				{ID: "tc1", Function: ToolFunction{Name: "t", Arguments: "not json"}},
			}},
		},
	}
	out, err := buildAnthropicRequest(req, 0)
	require.NoError(t, err)
	require.Len(t, out.Messages, 2)
	assert.Equal(t, " ", out.Messages[0].Content[0].Text)
	assert.JSONEq(t, `{"_raw_arguments":"not json"}`, string(out.Messages[1].Content[0].Input))
}

func TestBuildAnthropicRequestNoMessages(t *testing.T) {
	t.Parallel()

	_, err := buildAnthropicRequest(ChatRequest{Model: "claude-sonnet-4"}, 0)
	require.Error(t, err)
}

func TestAnthropicChatClientSuccess(t *testing.T) {
	t.Parallel()

	var seenPath, seenKey, seenVersion string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenPath, seenKey = r.URL.Path, r.Header.Get("x-api-key")
		seenVersion = r.Header.Get("anthropic-version")
		_, _ = w.Write([]byte(`{"id":"msg_1","model":"claude-sonnet-4","stop_reason":"tool_use",` +
			`"content":[{"type":"text","text":"scanning"},{"type":"tool_use","id":"tc1","name":"scan",` +
			`"input":{"url":"http://x"}}],` +
			`"usage":{"input_tokens":11,"output_tokens":7}}`))
	}))
	t.Cleanup(srv.Close)

	c := NewAnthropicChatClient(srv.URL, "key", 0, 0)
	resp, err := c.CreateChatCompletion(t.Context(), ChatRequest{
		Model:    "claude-sonnet-4",
		Messages: []ChatMessage{{Role: RoleUser, Content: "hi"}},
	})

	require.NoError(t, err)
	assert.Equal(t, "/v1/messages", seenPath)
	assert.Equal(t, "key", seenKey)
	assert.Equal(t, "2023-06-01", seenVersion)
	assert.Equal(t, "scanning", resp.Content)
	require.Len(t, resp.ToolCalls, 1)
	assert.Equal(t, "tc1", resp.ToolCalls[0].ID)
	assert.Equal(t, "scan", resp.ToolCalls[0].Function.Name)
	assert.JSONEq(t, `{"url":"http://x"}`, resp.ToolCalls[0].Function.Arguments)
	assert.Equal(t, 11, resp.Usage.PromptTokens)
	assert.Equal(t, 7, resp.Usage.CompletionTokens)
}

func TestAnthropicChatClientErrorClassification(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		status   int
		body     string
		expected ErrCategory
	}{
		{"rate limit", 429, `{"type":"error","error":{"type":"rate_limit_error","message":"slow down"}}`, ErrRateLimit},
		{"server error", 503, `{"type":"error","error":{"type":"api_error","message":"overloaded"}}`, ErrTransientNet},
		{"bad request", 400, `{"type":"error","error":{"type":"invalid_request_error","message":"bad role"}}`, ErrModelError},
		{"overflow", 400, `{"type":"error","error":{"type":"invalid_request_error","message":"prompt is too long: 250000 tokens > 200000 token maximum"}}`, ErrContextOverflow},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			t.Cleanup(srv.Close)

			c := NewAnthropicChatClient(srv.URL, "key", time.Second, 0)
			_, err := c.CreateChatCompletion(t.Context(), ChatRequest{
				Model:    "claude-sonnet-4",
				Messages: []ChatMessage{{Role: RoleUser, Content: "hi"}},
			})

			require.Error(t, err)
			cat, _ := Classify(err)
			assert.Equal(t, tc.expected, cat)
		})
	}
}

func TestAnthropicChatClientSendsConvertedBody(t *testing.T) {
	t.Parallel()

	var raw []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw = make([]byte, r.ContentLength)
		_, _ = r.Body.Read(raw)
		_, _ = w.Write([]byte(`{"id":"m","model":"claude-sonnet-4","content":[{"type":"text","text":"ok"}],"usage":{}}`))
	}))
	t.Cleanup(srv.Close)

	c := NewAnthropicChatClient(srv.URL, "", 0, 0)
	_, err := c.CreateChatCompletion(t.Context(), ChatRequest{
		Model: "claude-sonnet-4",
		Messages: []ChatMessage{
			{Role: RoleSystem, Content: "sys"},
			{Role: RoleUser, Content: "hi"},
		},
		Tools: []ChatTool{{Type: "function", Function: ChatToolSchema{
			Name: "scan", Parameters: map[string]any{"type": "object"},
		}}},
	})
	require.NoError(t, err)

	var body map[string]any
	require.NoError(t, json.Unmarshal(raw, &body))
	assert.Equal(t, "claude-sonnet-4", body["model"])
	assert.Equal(t, "40000", fmt.Sprint(body["max_tokens"]))
	assert.Contains(t, body, "system")
	assert.Contains(t, body, "tools")
}
