package harness

import (
	"fmt"

	"github.com/parkiyong/agentbox/pkg/protocol"
)

// CompactMessages keeps the conversation within maxChars by compacting older verbose tool
// responses while always preserving the system prompt, initial task, and the most recent turns.
func CompactMessages(messages []protocol.LLMMessage, maxChars int) []protocol.LLMMessage {
	if maxChars <= 0 {
		maxChars = 120_000
	}
	total := 0
	for _, m := range messages {
		total += len(m.Content)
	}
	if total <= maxChars || len(messages) <= 8 {
		return messages
	}

	out := make([]protocol.LLMMessage, len(messages))
	copy(out, messages)

	// Protect first 2 messages (system + user task) and last 6 messages (active working window).
	protectTailStart := len(out) - 6
	for i := 2; i < protectTailStart && total > maxChars; i++ {
		if out[i].Role == "tool" && len(out[i].Content) > 600 {
			saved := len(out[i].Content) - 420
			out[i].Content = out[i].Content[:300] +
				fmt.Sprintf("\n... [compacted %d chars of earlier tool output] ...\n", saved) +
				out[i].Content[len(out[i].Content)-120:]
			total -= saved
		}
	}
	return out
}
