package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sashabaranov/go-openai"

	"github.com/go-appsec/sectool-agents/secagent/util"
)

// ChatFormat identifies the wire API a ChatClient speaks.
type ChatFormat string

const (
	ChatFormatOpenAI    ChatFormat = "openai"
	ChatFormatAnthropic ChatFormat = "anthropic"
)

// DetectChatFormat resolves the wire API for a (baseURL, model) pair.
// forceAnthropic wins; an anthropic.com base URL follows; a claude-* model on
// the default (unset) endpoint follows; everything else is OpenAI-compatible.
func DetectChatFormat(baseURL, model string, forceAnthropic bool) ChatFormat {
	if forceAnthropic {
		return ChatFormatAnthropic
	}
	host := ""
	if u, err := url.Parse(baseURL); err == nil {
		host = strings.ToLower(u.Host)
	}
	if strings.Contains(host, "anthropic.com") {
		return ChatFormatAnthropic
	}
	if strings.HasPrefix(strings.ToLower(model), "claude") && host == "" {
		return ChatFormatAnthropic
	}
	return ChatFormatOpenAI
}

const (
	anthropicVersion         = "2023-06-01"
	anthropicDefaultBaseURL  = "https://api.anthropic.com"
	anthropicDefaultMaxToken = 40000
)

// Anthropic wire shapes. Only the subset of the Messages API this agent
// needs is modeled: text, tool_use, and tool_result blocks.
type antRequest struct {
	Model     string       `json:"model"`
	MaxTokens int          `json:"max_tokens"`
	System    []antBlock   `json:"system,omitempty"`
	Messages  []antWireMsg `json:"messages"`
	Tools     []antTool    `json:"tools,omitempty"`
}

type antWireMsg struct {
	Role    string     `json:"role"`
	Content []antBlock `json:"content"`
}

type antBlock struct {
	Type      string          `json:"type"`
	Text      string          `json:"text,omitempty"`
	ID        string          `json:"id,omitempty"`
	Name      string          `json:"name,omitempty"`
	Input     json.RawMessage `json:"input,omitempty"`
	ToolUseID string          `json:"tool_use_id,omitempty"`
	Content   []antBlock      `json:"content,omitempty"`
	IsError   bool            `json:"is_error,omitempty"`
}

type antTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	InputSchema json.RawMessage `json:"input_schema"`
}

type antResponse struct {
	ID         string     `json:"id"`
	Model      string     `json:"model"`
	StopReason string     `json:"stop_reason"`
	Content    []antBlock `json:"content"`
	Usage      struct {
		InputTokens  int `json:"input_tokens"`
		OutputTokens int `json:"output_tokens"`
	} `json:"usage"`
}

type antErrBody struct {
	Error struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error"`
}

// AnthropicChatClient speaks the Anthropic Messages API. It implements
// ChatClient so the OpenAI-shaped agent layer works unchanged.
type AnthropicChatClient struct {
	baseURL   string
	apiKey    string
	maxTokens int // default output cap when a request does not set one
	http      *http.Client
}

// NewAnthropicChatClient constructs a client; baseURL empty defaults to the
// public Anthropic API. maxTokens <= 0 selects the package default.
func NewAnthropicChatClient(baseURL, apiKey string, timeout time.Duration, maxTokens int) *AnthropicChatClient {
	if baseURL == "" {
		baseURL = anthropicDefaultBaseURL
	}
	if maxTokens <= 0 {
		maxTokens = anthropicDefaultMaxToken
	}
	return &AnthropicChatClient{
		baseURL:   strings.TrimSuffix(baseURL, "/"),
		apiKey:    apiKey,
		maxTokens: maxTokens,
		http:      util.NewHTTPClientWithTimeout(timeout),
	}
}

// CreateChatCompletion translates the OpenAI-shaped request onto the
// Messages API and maps the reply back to ChatResponse.
func (c *AnthropicChatClient) CreateChatCompletion(ctx context.Context, req ChatRequest) (ChatResponse, error) {
	body, err := buildAnthropicRequest(req, c.maxTokens)
	if err != nil {
		return ChatResponse{}, err
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return ChatResponse{}, fmt.Errorf("anthropic: encode request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/messages", bytes.NewReader(payload))
	if err != nil {
		return ChatResponse{}, err
	}
	httpReq.Header.Set("content-type", "application/json")
	httpReq.Header.Set("x-api-key", c.apiKey)
	httpReq.Header.Set("anthropic-version", anthropicVersion)

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return ChatResponse{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return ChatResponse{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return ChatResponse{}, anthropicHTTPError(resp.StatusCode, resp.Status, raw)
	}
	return parseAnthropicResponse(raw)
}

// buildAnthropicRequest converts ChatMessage history into Messages API shape:
// system messages lift to the top-level system field, assistant tool_calls
// become tool_use blocks, tool results become tool_result blocks on user
// messages, and consecutive same-role messages merge (the API requires strict
// user/assistant alternation).
func buildAnthropicRequest(req ChatRequest, defaultMaxTokens int) (antRequest, error) {
	out := antRequest{
		Model:     req.Model,
		MaxTokens: defaultMaxTokens,
		Messages:  make([]antWireMsg, 0, len(req.Messages)),
	}
	if req.MaxTokens > 0 {
		out.MaxTokens = req.MaxTokens
	}

	var sys []string
	for _, m := range req.Messages {
		switch m.Role {
		case RoleSystem:
			if strings.TrimSpace(m.Content) != "" {
				sys = append(sys, m.Content)
			}
		case RoleAssistant:
			var blocks []antBlock
			if m.Content != "" {
				blocks = append(blocks, antBlock{Type: "text", Text: m.Content})
			}
			for _, tc := range m.ToolCalls {
				blocks = append(blocks, antBlock{
					Type:  "tool_use",
					ID:    tc.ID,
					Name:  tc.Function.Name,
					Input: anthropicToolInput(tc.Function.Arguments),
				})
			}
			if len(blocks) > 0 {
				appendAnthropicMsg(&out, RoleAssistant, blocks)
			}
		case RoleTool:
			blocks := []antBlock{{
				Type:      "tool_result",
				ToolUseID: m.ToolCallID,
				Content:   []antBlock{{Type: "text", Text: anthropicPad(m.Content)}},
			}}
			appendAnthropicMsg(&out, RoleUser, blocks)
		default: // user
			blocks := []antBlock{{Type: "text", Text: anthropicPad(m.Content)}}
			appendAnthropicMsg(&out, RoleUser, blocks)
		}
	}
	if len(sys) > 0 {
		out.System = []antBlock{{Type: "text", Text: strings.Join(sys, "\n\n")}}
	}

	if len(req.Tools) > 0 {
		out.Tools = make([]antTool, 0, len(req.Tools))
		for _, t := range req.Tools {
			schema, err := json.Marshal(t.Function.Parameters)
			if err != nil || t.Function.Parameters == nil {
				schema = []byte(`{"type":"object"}`)
			}
			out.Tools = append(out.Tools, antTool{
				Name:        t.Function.Name,
				Description: t.Function.Description,
				InputSchema: schema,
			})
		}
	}

	if len(out.Messages) == 0 {
		return antRequest{}, errors.New("anthropic: request has no convertible messages")
	}
	if out.Messages[0].Role != RoleUser {
		return antRequest{}, fmt.Errorf("anthropic: first message must be user, got %q", out.Messages[0].Role)
	}
	return out, nil
}

// appendAnthropicMsg appends blocks under role, merging into the previous
// message when roles match so the wire alternation invariant holds.
func appendAnthropicMsg(req *antRequest, role string, blocks []antBlock) {
	if n := len(req.Messages); n > 0 && req.Messages[n-1].Role == role {
		req.Messages[n-1].Content = append(req.Messages[n-1].Content, blocks...)
		return
	}
	req.Messages = append(req.Messages, antWireMsg{Role: role, Content: blocks})
}

// anthropicPad substitutes a placeholder for empty content, which the API rejects.
func anthropicPad(content string) string {
	if strings.TrimSpace(content) == "" {
		return " "
	}
	return content
}

// anthropicToolInput converts an OpenAI arguments string into a raw JSON
// object. Invalid arguments are wrapped so the call stays routable and the
// model sees the repair error instead of an HTTP 400.
func anthropicToolInput(args string) json.RawMessage {
	trimmed := strings.TrimSpace(args)
	if trimmed == "" {
		return json.RawMessage("{}")
	}
	if json.Valid([]byte(trimmed)) {
		return json.RawMessage(trimmed)
	}
	b, err := json.Marshal(map[string]string{"_raw_arguments": args})
	if err != nil {
		return json.RawMessage("{}")
	}
	return b
}

// anthropicHTTPError builds an openai.APIError so Classify's status-based
// retry policy applies unchanged to Anthropic endpoints.
func anthropicHTTPError(status int, statusText string, raw []byte) error {
	var body antErrBody
	_ = json.Unmarshal(raw, &body)
	msg := strings.TrimSpace(body.Error.Message)
	if msg == "" {
		msg = strings.TrimSpace(string(raw))
	}
	if msg == "" {
		msg = body.Error.Type
	}
	return &openai.APIError{
		HTTPStatusCode: status,
		HTTPStatus:     statusText,
		Type:           body.Error.Type,
		Message:        msg,
	}
}

// parseAnthropicResponse maps content blocks back onto the OpenAI-shaped reply.
func parseAnthropicResponse(raw []byte) (ChatResponse, error) {
	var wire antResponse
	if err := json.Unmarshal(raw, &wire); err != nil {
		return ChatResponse{}, fmt.Errorf("anthropic: decode response: %w", err)
	}
	var texts []string
	var calls []ToolCall
	for _, b := range wire.Content {
		switch b.Type {
		case "text":
			if b.Text != "" {
				texts = append(texts, b.Text)
			}
		case "tool_use":
			input := b.Input
			if len(input) == 0 {
				input = json.RawMessage("{}")
			}
			calls = append(calls, ToolCall{
				ID:   b.ID,
				Type: "function",
				Function: ToolFunction{
					Name:      b.Name,
					Arguments: string(input),
				},
			})
		}
	}
	return ChatResponse{
		Content:   strings.Join(texts, "\n"),
		ToolCalls: calls,
		Usage: Usage{
			PromptTokens:     wire.Usage.InputTokens,
			CompletionTokens: wire.Usage.OutputTokens,
			TotalTokens:      wire.Usage.InputTokens + wire.Usage.OutputTokens,
		},
		Model: wire.Model,
	}, nil
}
