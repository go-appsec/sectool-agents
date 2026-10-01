package agent

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOpenAIChatClient_EmptyChoices(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"x","object":"chat.completion","model":"m",` +
			`"choices":[],"usage":{"prompt_tokens":11,"completion_tokens":7,"total_tokens":18}}`))
	}))
	t.Cleanup(srv.Close)

	c := NewOpenAIChatClient(srv.URL, "key", 0)
	_, err := c.CreateChatCompletion(t.Context(), ChatRequest{Model: "m"})

	require.ErrorIs(t, err, ErrEmptyChoices)
	// usage detail keeps usage-only responses distinguishable
	assert.Contains(t, err.Error(), "model=m")
	assert.Contains(t, err.Error(), "prompt_tokens=11")
	assert.Contains(t, err.Error(), "completion_tokens=7")

	cat, _ := Classify(err)
	assert.Equal(t, ErrTransientNet, cat)
}

func TestOpenAIChatClient_Success(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"x","object":"chat.completion","model":"m",` +
			`"choices":[{"index":0,"finish_reason":"stop","message":{"role":"assistant","content":"hi"}}],` +
			`"usage":{"prompt_tokens":3,"completion_tokens":1,"total_tokens":4}}`))
	}))
	t.Cleanup(srv.Close)

	c := NewOpenAIChatClient(srv.URL, "key", 0)
	resp, err := c.CreateChatCompletion(t.Context(), ChatRequest{Model: "m"})

	require.NoError(t, err)
	assert.Equal(t, "hi", resp.Content)
	assert.Equal(t, "m", resp.Model)
	assert.Equal(t, 3, resp.Usage.PromptTokens)
	assert.Equal(t, 1, resp.Usage.CompletionTokens)
}
