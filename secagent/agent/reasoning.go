package agent

import (
	"context"
	"slices"
	"sync"
	"time"
)

// ReasoningFormat describes how a model surfaces its thinking on the OpenAI-compatible endpoint.
type ReasoningFormat int

const (
	// ReasoningFormatUnknown is the pre-detection / probe-failed state.
	// NewReasoningHandler maps it to the inline handler.
	ReasoningFormatUnknown ReasoningFormat = iota
	// ReasoningFormatNone model does not emit any thinking (small / non-reasoning).
	ReasoningFormatNone
	// ReasoningFormatInline model embeds `<think>...</think>` inside content.
	ReasoningFormatInline
	// ReasoningFormatStructured model populates the `reasoning_content` field.
	ReasoningFormatStructured
)

// String returns the canonical lowercase name, suitable for log fields.
func (f ReasoningFormat) String() string {
	switch f {
	case ReasoningFormatNone:
		return "none"
	case ReasoningFormatInline:
		return "inline"
	case ReasoningFormatStructured:
		return "structured"
	default:
		return "unknown"
	}
}

// ReasoningHandler encapsulates per-model reasoning behavior.
type ReasoningHandler interface {
	// Format returns the detected reasoning format.
	Format() ReasoningFormat

	// Ingest splits resp into content and reasoning suitable for history storage.
	Ingest(resp ChatResponse) (content, reasoning string)

	// Replay returns msgs filtered for the next send, retaining reasoning
	// on the last keepLastN messages where applicable.
	Replay(msgs []Message, keepLastN int) []Message

	// ForSummary returns msgs converted to inline-think shape for summary prompts.
	ForSummary(msgs []Message) []Message

	// Extract returns a confident single-line summary from resp, or "" to fall back to Tail.
	Extract(resp ChatResponse) string

	// Tail returns a best-effort reasoning fragment from resp when Extract produced nothing.
	Tail(resp ChatResponse) string
}

// NewReasoningHandler returns the handler for f. ReasoningFormatUnknown maps to the inline handler.
func NewReasoningHandler(f ReasoningFormat) ReasoningHandler {
	switch f {
	case ReasoningFormatNone:
		return noReasoningHandler{}
	case ReasoningFormatStructured:
		return structuredHandler{}
	default:
		return inlineHandler{}
	}
}

// inlineHandler handles models that emit `<think>...</think>` in content.
type inlineHandler struct{}

func (inlineHandler) Format() ReasoningFormat { return ReasoningFormatInline }

func (inlineHandler) Ingest(resp ChatResponse) (string, string) {
	return resp.Content, ""
}

func (inlineHandler) Replay(msgs []Message, keepLastN int) []Message {
	return FilterThinkBlocks(msgs, keepLastN)
}

func (inlineHandler) ForSummary(msgs []Message) []Message {
	// Inline reasoning lives in Content already; summary model sees it
	// exactly as the agent does.
	return msgs
}

func (inlineHandler) Extract(resp ChatResponse) string {
	return ExtractProse(resp.Content)
}

func (inlineHandler) Tail(resp ChatResponse) string {
	return TruncatedThinkTail(resp.Content)
}

// structuredHandler handles models that populate `reasoning_content`.
type structuredHandler struct{}

func (structuredHandler) Format() ReasoningFormat { return ReasoningFormatStructured }

func (structuredHandler) Ingest(resp ChatResponse) (string, string) {
	return resp.Content, resp.ReasoningContent
}

func (structuredHandler) Replay(msgs []Message, _ int) []Message {
	// Structured reasoning is ephemeral. Blank it on every replayed message so it never reaches the wire.
	out := slices.Clone(msgs)
	for i := range out {
		if out[i].Role == RoleAssistant {
			out[i].ReasoningContent = ""
		}
	}
	return out
}

func (structuredHandler) ForSummary(msgs []Message) []Message {
	// Unify to inline: wrap structured reasoning as <think>...</think> and prepend to Content so the
	// summary prompt looks the same regardless of source. Safe for one-shot summary calls;
	// the summary model's output is processed via StripThinkBlocks after.
	out := slices.Clone(msgs)
	for i := range out {
		m := out[i]
		if m.Role != RoleAssistant || m.ReasoningContent == "" {
			continue
		}
		wrapped := "<think>" + m.ReasoningContent + "</think>"
		if m.Content != "" {
			wrapped = wrapped + "\n" + m.Content
		}
		out[i].Content = wrapped
		out[i].ReasoningContent = ""
	}
	return out
}

func (structuredHandler) Extract(resp ChatResponse) string {
	// reasoning models occasionally populate both fields, and when they do, Content is the "clean" output
	if line := ExtractProse(resp.Content); line != "" {
		return line
	}
	// Many reasoning models emit a Final:/Output:/Answer: marker inside their reasoning before the token cap;
	// salvage that as the confident summary instead of showing meta-chatter.
	if resp.ReasoningContent != "" {
		if line := ExtractMarkedOutput(resp.ReasoningContent); line != "" {
			return line
		}
	}
	return ""
}

func (structuredHandler) Tail(resp ChatResponse) string {
	// Content may still be a reasonable source (rare: truncated mid-inline),
	// so try that first, then fall back to the structured field.
	if tail := TruncatedThinkTail(resp.Content); tail != "" {
		return tail
	}
	if resp.ReasoningContent != "" {
		return compactThinkTail(resp.ReasoningContent, 240)
	}
	return ""
}

// noReasoningHandler is a pass-through for models that don't emit thinking.
type noReasoningHandler struct{}

func (noReasoningHandler) Format() ReasoningFormat                   { return ReasoningFormatNone }
func (noReasoningHandler) Ingest(resp ChatResponse) (string, string) { return resp.Content, "" }
func (noReasoningHandler) Replay(msgs []Message, _ int) []Message    { return msgs }
func (noReasoningHandler) ForSummary(msgs []Message) []Message       { return msgs }
func (noReasoningHandler) Extract(resp ChatResponse) string          { return ExtractProse(resp.Content) }
func (noReasoningHandler) Tail(_ ChatResponse) string                { return "" }

// reasoningProbePrompt induces multi-step thinking in reasoning-trained
// models while staying cheap to classify.
const reasoningProbePrompt = "If the sky is blue, why is the sun orange and the moon white?"

// reasoningProbeMaxTokens caps probe output. Kept high so long-thinking models reach content before truncation.
const reasoningProbeMaxTokens = 20000

// SummaryReasoningEffort is forwarded as `reasoning_effort` on summary calls (narrator + per-agent status).
// "none" disables reasoning on supporting backends; unsupported backends ignore it.
const SummaryReasoningEffort = "none"

// CompressionReasoningEffort is forwarded as reasoning_effort on iteration-boundary history compression.
// "low" preserves evidence selection without burning context budget.
const CompressionReasoningEffort = "low"

// reasoningProbeTimeout bounds probe latency.
const reasoningProbeTimeout = 5 * time.Minute

// DetectReasoningFormat probes model via client and returns its detected
// reasoning format. Errors return ReasoningFormatUnknown.
func DetectReasoningFormat(ctx context.Context, client ChatClient, model string) (ReasoningFormat, error) {
	ctx, cancel := context.WithTimeout(ctx, reasoningProbeTimeout)
	defer cancel()
	resp, err := client.CreateChatCompletion(ctx, ChatRequest{
		Model: model,
		Messages: []ChatMessage{
			{Role: RoleUser, Content: reasoningProbePrompt},
		},
		MaxTokens: reasoningProbeMaxTokens,
	})
	if err != nil {
		return ReasoningFormatUnknown, err
	} else if resp.ReasoningContent != "" {
		return ReasoningFormatStructured, nil
	} else if HasInlineThink(resp.Content) {
		return ReasoningFormatInline, nil
	}
	return ReasoningFormatNone, nil
}

// ReasoningFormatCache memoizes detection results keyed by (baseURL, model).
type ReasoningFormatCache struct {
	mu    sync.Mutex
	byKey map[string]ReasoningFormat
}

// NewReasoningFormatCache constructs an empty cache.
func NewReasoningFormatCache() *ReasoningFormatCache {
	return &ReasoningFormatCache{byKey: map[string]ReasoningFormat{}}
}

// Resolve returns the cached format for (baseURL, model) or runs detection once and caches the result.
// Detection errors cache ReasoningFormatUnknown. onDetect fires after each real probe; pass nil to skip.
func (c *ReasoningFormatCache) Resolve(ctx context.Context, client ChatClient, baseURL, model string,
	onDetect func(format ReasoningFormat, elapsed time.Duration, err error)) ReasoningFormat {
	key := baseURL + "|" + model
	c.mu.Lock()
	if f, ok := c.byKey[key]; ok {
		c.mu.Unlock()
		return f
	}
	c.mu.Unlock()
	start := time.Now()
	f, err := DetectReasoningFormat(ctx, client, model)
	if onDetect != nil {
		onDetect(f, time.Since(start), err)
	}
	c.mu.Lock()
	c.byKey[key] = f
	c.mu.Unlock()
	return f
}
