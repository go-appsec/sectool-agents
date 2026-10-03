package config

import (
	"errors"
	"flag"
	"fmt"
	iofs "io/fs"
	"os"
	"strings"
	"syscall"
	"time"
)

// Config is the full runtime configuration parsed from flags.
type Config struct {
	// Connection
	BaseURL       string
	APIKey        string
	Model         string // workers, verifier, director, summarizer, dedup/merge classify
	LogModel      string // narrator; defaults to Model
	AgentPoolSize int    // shared pool size

	// API format
	AnthropicMessages  bool // force the Anthropic Messages API; off = auto-detect
	AnthropicMaxTokens int  // default max_tokens for Messages API requests

	// Context / compaction
	MaxContext         int // workers, verifier, director context window
	LogMaxContext      int // log-model context window; defaults to MaxContext
	ToolResultMaxBytes int
	HighWatermark      float64
	LowWatermark       float64
	KeepTurns          int
	KeepThinkTurns     int

	// Sectool
	ProxyPort        int
	MCPPort          int
	SkipVersionCheck bool   // skip the best-effort sectool version staleness check at startup
	SectoolBinary    string // user preference via --sectool-bin; main overwrites with the resolved absolute path
	SectoolStatePath string // resolved at startup (not flag-backed); set by main

	// Loop
	Prompt           string
	MaxIterations    int
	MaxWorkers       int
	AutonomousBudget int
	TurnTimeout      time.Duration
	PerToolTimeout   time.Duration
	MaxParallelTools int
	MaxTurnsPerAgent int
	FindingsDir      string
	SkipRecon        bool // iter 1 spawns a normal worker instead of recon
	AllowBash        bool // workers, recon, and verifier get an unrestricted `bash` tool

	// Stall
	StallWarnAfter int
	StallStopAfter int

	// Logging
	NarrateInterval time.Duration
	LogFile         string
}

// NarrateTimeout returns the per-summary narrator call timeout.
func (c *Config) NarrateTimeout() time.Duration {
	// 15-minute floor so slow reasoning models don't time out routinely
	return max(2*c.NarrateInterval, 15*time.Minute)
}

// LogPoolSize returns the dedicated log-pool capacity.
func (c *Config) LogPoolSize() int {
	// shared backend -> 1 slot; distinct log model -> 2 so async narration can overlap
	if c.LogModel == "" || c.LogModel == c.Model {
		return 1
	}
	return 2
}

const (
	MinWorkers          = 1
	MaxWorkers          = 5
	MaxAutonomousBudget = 20
	DefaultAutoBudget   = 8
	MinKeepTurns        = 1
	MaxKeepTurns        = 32
)

// Parse parses args against fs and returns a populated Config.
func Parse(fs *flag.FlagSet, args []string) (*Config, error) {
	c := &Config{}

	fs.StringVar(&c.BaseURL, "base-url", "", "OpenAI-compatible base URL")
	fs.StringVar(&c.APIKey, "api-key", "", "optional API key")
	fs.StringVar(&c.Model, "model", "", "main model ID (workers, verifier, director, summarizer)")
	fs.StringVar(&c.LogModel, "log-model", "", "model ID for the narrator; defaults to --model")
	fs.IntVar(&c.AgentPoolSize, "agent-pool-size", 4, "concurrent model request bound (shared pool)")

	fs.BoolVar(&c.AnthropicMessages, "anthropic-messages", false,
		"force the Anthropic Messages API (default: auto-detect from base URL and model)")
	fs.IntVar(&c.AnthropicMaxTokens, "anthropic-max-tokens", 0,
		"default max_tokens for Anthropic Messages requests (0 = 40000)")

	fs.IntVar(&c.MaxContext, "max-context", 200000, "main-model context window (tokens)")
	fs.IntVar(&c.LogMaxContext, "log-max-context", 0, "log-model context window; 0 inherits --max-context")
	fs.IntVar(&c.ToolResultMaxBytes, "tool-result-max-bytes", 8192, "per-tool-result truncation cap")
	fs.Float64Var(&c.HighWatermark, "compaction-high-watermark", 0.80, "compaction trigger fraction, in (0, 1]")
	fs.Float64Var(&c.LowWatermark, "compaction-low-watermark", 0.40, "compaction target fraction, must be below --compaction-high-watermark")
	fs.IntVar(&c.KeepTurns, "compaction-keep-turns", 4, "turns never compacted")
	fs.IntVar(&c.KeepThinkTurns, "keep-think-turns", 0, "assistant messages to preserve <think> blocks on when replaying history (0 = auto: 4 if max-context ≤ 128k, else 8)")

	fs.IntVar(&c.ProxyPort, "proxy-port", 8181, "sectool proxy port")
	fs.IntVar(&c.MCPPort, "mcp-port", 9119, "sectool MCP port")
	fs.StringVar(&c.SectoolBinary, "sectool-bin", "", "path to sectool binary (default: alongside secagent or on $PATH)")
	fs.BoolVar(&c.SkipVersionCheck, "skip-version-check", false, "skip the best-effort sectool version staleness check at startup")

	fs.StringVar(&c.Prompt, "prompt", "", "initial task prompt or path to a prompt file (required)")
	fs.IntVar(&c.MaxIterations, "max-iterations", 30, "hard iteration cap")
	fs.IntVar(&c.MaxWorkers, "max-workers", 4, "max parallel workers")
	fs.IntVar(&c.AutonomousBudget, "autonomous-budget", DefaultAutoBudget, "turns per worker per iteration")
	// Defaults generous for slow local models with long tool chains
	fs.DurationVar(&c.TurnTimeout, "turn-timeout", 10*time.Minute, "per-turn ctx timeout")
	fs.DurationVar(&c.PerToolTimeout, "per-tool-timeout", 5*time.Minute, "per-tool-call ctx timeout")
	fs.IntVar(&c.MaxParallelTools, "max-parallel-tools", 4, "max concurrent in-flight tool calls per assistant response")
	fs.IntVar(&c.MaxTurnsPerAgent, "max-turns-per-agent", 100, "hard cap per Drain chain")
	fs.StringVar(&c.FindingsDir, "findings-dir", "./findings", "finding report directory")
	fs.BoolVar(&c.SkipRecon, "skip-recon", false, "skip the iter-1 recon pass; iter 1 runs a normal testing worker against cfg.Prompt")
	fs.BoolVar(&c.AllowBash, "allow-bash", false, "give workers, recon, and the verifier an unrestricted bash tool for arbitrary shell command execution (directors direct workers for shell work)")

	fs.IntVar(&c.StallWarnAfter, "stall-warn-after", 3, "silent runs before director warning")
	fs.IntVar(&c.StallStopAfter, "stall-stop-after", 4, "silent runs before force-stop")

	fs.DurationVar(&c.NarrateInterval, "narrate-interval", 5*time.Minute, "min interval between async narrator summaries (0 disables)")
	fs.StringVar(&c.LogFile, "log-file", "secagent.log", "structured log destination")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if c.Prompt == "" {
		return nil, errors.New("--prompt is required")
	}
	if info, err := os.Stat(c.Prompt); err == nil && info.Mode().IsRegular() {
		data, err := os.ReadFile(c.Prompt)
		if err != nil {
			return nil, fmt.Errorf("--prompt: read %s: %w", c.Prompt, err)
		}
		trimmed := strings.TrimSpace(string(data))
		if trimmed == "" {
			return nil, fmt.Errorf("--prompt: file %s is empty", c.Prompt)
		}
		c.Prompt = trimmed
	} else if err != nil && !errors.Is(err, iofs.ErrNotExist) && !errors.Is(err, syscall.ENAMETOOLONG) {
		// ENAMETOOLONG means the value is literal prompt text too long to be a path
		return nil, fmt.Errorf("--prompt: stat %s: %w", c.Prompt, err)
	}
	c.MaxWorkers = min(max(c.MaxWorkers, MinWorkers), MaxWorkers)
	c.AutonomousBudget = min(max(c.AutonomousBudget, 1), MaxAutonomousBudget)
	if c.HighWatermark <= 0 || c.HighWatermark > 1 {
		return nil, fmt.Errorf("--compaction-high-watermark: %g outside (0, 1]", c.HighWatermark)
	}
	if c.LowWatermark <= 0 || c.LowWatermark >= c.HighWatermark {
		return nil, fmt.Errorf("--compaction-low-watermark: %g must be in (0, --compaction-high-watermark) (%g)",
			c.LowWatermark, c.HighWatermark)
	}
	c.KeepTurns = min(max(c.KeepTurns, MinKeepTurns), MaxKeepTurns)
	if c.LogModel == "" {
		c.LogModel = c.Model
	}
	if c.LogMaxContext <= 0 {
		c.LogMaxContext = c.MaxContext
	}
	if c.AnthropicMaxTokens < 0 {
		return nil, fmt.Errorf("--anthropic-max-tokens: %d must be >= 0", c.AnthropicMaxTokens)
	}
	return c, nil
}

// EffectiveKeepThinkTurns returns how many recent assistant messages should retain their <think> blocks when replaying history.
func (c *Config) EffectiveKeepThinkTurns(maxContext int) int {
	if c.KeepThinkTurns > 0 {
		return c.KeepThinkTurns
	}
	// tighter window for small contexts; think blocks can be large
	if maxContext <= 128_000 {
		return 4
	}
	return 8
}
