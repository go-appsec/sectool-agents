package history

import (
	"context"
	"strings"

	"github.com/go-appsec/secagent/agent"
)

// RunOneShot runs a single chat completion via pool; returns the trimmed response content.
func RunOneShot(ctx context.Context, pool *agent.ClientPool,
	model, system, user string, maxTokens int, reasoningEffort string, temperature *float32) (string, error) {
	client, err := pool.Acquire(ctx)
	if err != nil {
		return "", err
	}
	defer pool.Release(client)
	resp, err := client.CreateChatCompletion(ctx, agent.ChatRequest{
		Model: model,
		Messages: []agent.ChatMessage{
			{Role: "system", Content: system},
			{Role: "user", Content: user},
		},
		MaxTokens:       maxTokens,
		ReasoningEffort: reasoningEffort,
		Temperature:     temperature,
	})
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(resp.Content), nil
}
