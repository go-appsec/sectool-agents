package orchestrator

import (
	"github.com/go-analyze/bulk"

	"github.com/go-appsec/secagent/agent"
	"github.com/go-appsec/secagent/history"
)

// DirectorMsgMeta tags one DirectorChat message with the worker it belongs
// to and the iteration it was added in. WorkerID==0 means director-owned.
type DirectorMsgMeta struct {
	WorkerID int
	Iter     int
}

// DirectorChat is the canonical director chat record. Messages and Meta are parallel slices.
type DirectorChat struct {
	Messages []agent.Message
	Meta     []DirectorMsgMeta
}

// NewDirectorChat returns an empty DirectorChat.
func NewDirectorChat() *DirectorChat {
	return &DirectorChat{}
}

// Append records msg tagged with workerID and iter. workerID=0 means director-owned.
func (c *DirectorChat) Append(msg agent.Message, workerID, iter int) {
	c.Messages = append(c.Messages, msg)
	c.Meta = append(c.Meta, DirectorMsgMeta{WorkerID: workerID, Iter: iter})
}

// AppendWorkerActivity records msgs in order, each tagged with workerID and iter.
func (c *DirectorChat) AppendWorkerActivity(workerID, iter int, msgs []agent.Message) {
	for _, m := range msgs {
		c.Append(m, workerID, iter)
	}
}

// ReplaceWorkerWithSummary replaces every message tagged with workerID with one
// user-role summary message tagged director-owned. No-op when workerID has no messages.
func (c *DirectorChat) ReplaceWorkerWithSummary(workerID int, summary string, iter int) {
	if workerID <= 0 {
		return
	}
	firstIdx := -1
	keptMsgs := make([]agent.Message, 0, len(c.Messages))
	keptMeta := make([]DirectorMsgMeta, 0, len(c.Meta))
	for i := range c.Messages {
		if c.Meta[i].WorkerID == workerID {
			if firstIdx < 0 {
				firstIdx = len(keptMsgs)
			}
			continue
		}
		keptMsgs = append(keptMsgs, c.Messages[i])
		keptMeta = append(keptMeta, c.Meta[i])
	}
	if firstIdx < 0 {
		return
	}
	summaryMsg := agent.Message{Role: "user", Content: summary}
	summaryMeta := DirectorMsgMeta{WorkerID: 0, Iter: iter}
	c.Messages = append(keptMsgs[:firstIdx],
		append([]agent.Message{summaryMsg}, keptMsgs[firstIdx:]...)...)
	c.Meta = append(keptMeta[:firstIdx],
		append([]DirectorMsgMeta{summaryMeta}, keptMeta[firstIdx:]...)...)
}

// ApplyWorkerSelfPrune mirrors a worker agent's self-prune onto the
// director chat, scoped to messages tagged for workerID. Messages from
// other workers (or director-owned) pass through. Returns dropped count.
func (c *DirectorChat) ApplyWorkerSelfPrune(workerID int, dropIDs []string) int {
	if workerID <= 0 || len(dropIDs) == 0 {
		return 0
	}
	dropSet := bulk.SliceToSet(bulk.SliceFilter(func(s string) bool { return s != "" }, dropIDs))
	if len(dropSet) == 0 {
		return 0
	}
	keptMsgs, keptIndices, dropped := history.PruneToolResults(
		c.Messages, dropSet,
		func(i int) bool { return c.Meta[i].WorkerID == workerID },
	)
	keptMeta := make([]DirectorMsgMeta, 0, len(keptIndices))
	for _, i := range keptIndices {
		keptMeta = append(keptMeta, c.Meta[i])
	}
	c.Messages = keptMsgs
	c.Meta = keptMeta
	return dropped
}

// RenderForWorker returns a deep-copied view of the chat where messages for currentWorkerID and
// director-owned messages are raw, and other workers' messages are think-stripped + tool-stubbed.
func (c *DirectorChat) RenderForWorker(currentWorkerID int) []agent.Message {
	out := make([]agent.Message, len(c.Messages))
	for i, m := range c.Messages {
		out[i] = m
		w := c.Meta[i].WorkerID
		if w == 0 || w == currentWorkerID {
			continue
		}
		agent.StripAssistantThink(&out[i])
		agent.StubToolResult(&out[i])
	}
	NormalizeEmptyContent(out)
	return out
}

// RenderForSynthesis returns a deep-copied view of the chat where director-owned messages
// are raw and every worker's messages are think-stripped + tool-stubbed.
func (c *DirectorChat) RenderForSynthesis() []agent.Message {
	out := make([]agent.Message, len(c.Messages))
	for i, m := range c.Messages {
		out[i] = m
		if c.Meta[i].WorkerID == 0 {
			continue
		}

		agent.StripAssistantThink(&out[i])
		agent.StubToolResult(&out[i])
	}
	NormalizeEmptyContent(out)
	return out
}

// NormalizeEmptyContent rewrites in place any user/system/tool message whose Content is
// empty to a descriptive placeholder. Assistant messages are left untouched.
func NormalizeEmptyContent(msgs []agent.Message) {
	for i := range msgs {
		if msgs[i].Content != "" || msgs[i].Role == agent.RoleAssistant {
			continue
		}

		switch msgs[i].Role {
		case agent.RoleTool:
			msgs[i].Content = "(tool returned no output)"
		default:
			msgs[i].Content = "(no content)"
		}
	}
}
