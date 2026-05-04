package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	mcpclient "github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/client/transport"
	"github.com/mark3labs/mcp-go/mcp"

	"github.com/go-appsec/secagent/agent"
	"github.com/go-appsec/secagent/util"
)

// Client wraps a mcp-go streamable-HTTP client.
type Client struct {
	c *mcpclient.Client
}

// Connect dials url and initializes the MCP session. Closes the underlying client on initialize failure.
func Connect(ctx context.Context, url string) (*Client, error) {
	cl, err := mcpclient.NewStreamableHttpClient(url, transport.WithHTTPBasicClient(util.HTTPClient))
	if err != nil {
		return nil, fmt.Errorf("mcp: new client: %w", err)
	}
	initReq := mcp.InitializeRequest{}
	initReq.Params.ProtocolVersion = mcp.LATEST_PROTOCOL_VERSION
	initReq.Params.ClientInfo = mcp.Implementation{Name: "secagent", Version: "0.1.0"}
	initReq.Params.Capabilities = mcp.ClientCapabilities{}
	if _, err := cl.Initialize(ctx, initReq); err != nil {
		_ = cl.Close()
		return nil, fmt.Errorf("mcp: initialize: %w", err)
	}
	return &Client{c: cl}, nil
}

func (c *Client) Close() error {
	if c == nil {
		return nil
	}
	return c.c.Close()
}

// ListTools fetches the current tool list.
func (c *Client) ListTools(ctx context.Context) ([]mcp.Tool, error) {
	res, err := c.c.ListTools(ctx, mcp.ListToolsRequest{})
	if err != nil {
		return nil, err
	}
	return res.Tools, nil
}

// CallTool invokes a tool and returns its concatenated text content and the is_error flag from the response.
func (c *Client) CallTool(ctx context.Context, name string, args map[string]any) (string, bool, error) {
	req := mcp.CallToolRequest{Params: mcp.CallToolParams{Name: name, Arguments: args}}
	res, err := c.c.CallTool(ctx, req)
	if err != nil {
		return "", true, err
	}
	var sb strings.Builder
	for i, ci := range res.Content {
		if tc, ok := ci.(mcp.TextContent); ok {
			if i > 0 {
				sb.WriteString("\n")
			}
			sb.WriteString(tc.Text)
		}
	}
	return sb.String(), res.IsError, nil
}

// BuildToolDefs returns one agent.ToolDef per sectool tool. Names are
// prefixed with prefix; results are truncated to maxResultBytes.
func (c *Client) BuildToolDefs(ctx context.Context, prefix string, maxResultBytes int) ([]agent.ToolDef, error) {
	tools, err := c.ListTools(ctx)
	if err != nil {
		return nil, err
	}
	defs := make([]agent.ToolDef, 0, len(tools))
	for _, t := range tools {
		raw, err := json.Marshal(t.InputSchema)
		if err != nil {
			return nil, fmt.Errorf("mcp: schema for %s: %w", t.Name, err)
		}
		var schema map[string]any
		if err := json.Unmarshal(raw, &schema); err != nil {
			return nil, fmt.Errorf("mcp: schema for %s: %w", t.Name, err)
		}
		defs = append(defs, agent.ToolDef{
			Name:        prefix + t.Name,
			Description: t.Description,
			Schema:      schema,
			Handler:     c.dispatchHandler(t.Name, maxResultBytes),
		})
	}
	return defs, nil
}

// dispatchHandler returns a ToolHandler that calls realName via this client.
func (c *Client) dispatchHandler(realName string, maxResultBytes int) agent.ToolHandler {
	return func(ctx context.Context, args json.RawMessage) agent.ToolResult {
		var m map[string]any
		if len(args) > 0 {
			if err := json.Unmarshal(args, &m); err != nil {
				return agent.ToolResult{
					Text:    fmt.Sprintf("ERROR: MCP tool %q received invalid JSON: %v", realName, err),
					IsError: true,
				}
			}
		}
		text, isErr, err := c.CallTool(ctx, realName, m)
		if err != nil {
			return agent.ToolResult{
				Text:    fmt.Sprintf("ERROR: MCP tool %q failed: %v", realName, err),
				IsError: true,
			}
		}
		text = truncateResult(text, maxResultBytes)
		return agent.ToolResult{Text: text, IsError: isErr}
	}
}

func truncateResult(s string, maxBytes int) string {
	if maxBytes <= 0 || len(s) <= maxBytes {
		return s
	}
	notice := fmt.Sprintf(
		"\n…(truncated: %d of %d bytes shown. Reduce scope — e.g., add filters, raise `since`, or request specific fields — then call again.)",
		maxBytes, len(s),
	)
	return s[:maxBytes] + notice
}
