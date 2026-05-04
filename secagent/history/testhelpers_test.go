package history

import (
	"context"
	"sync"

	"github.com/go-appsec/secagent/agent"
)

// scriptedClient returns a canned response and captures every incoming ChatRequest so tests can assert request params.
type scriptedClient struct {
	mu       sync.Mutex
	response string
	err      error
	requests []agent.ChatRequest
}

func (c *scriptedClient) CreateChatCompletion(_ context.Context, req agent.ChatRequest) (agent.ChatResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.requests = append(c.requests, req)
	if c.err != nil {
		return agent.ChatResponse{}, c.err
	}
	return agent.ChatResponse{Content: c.response}, nil
}

func poolOf(c agent.ChatClient) *agent.ClientPool {
	return agent.NewClientPoolWithClients([]agent.ChatClient{c})
}
