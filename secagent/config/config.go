package config

import (
	"errors"
	"flag"
	"time"
)

// Config is the full runtime configuration parsed from flags.
type Config struct {
	// Connection
	BaseURL       string
	APIKey        string
	Model         string // workers, verifier, director, summarizer, verifier-side dedup
	LogModel      string // narrator, candidate-dedup classifier, async-merge; defaults to Model
	AgentPoolSize int    // shared pool size

	// Context / compaction
	MaxContext         int // workers, verifier, director context window
	LogMaxContext      int // log-model context window; defaults to MaxContext
	ToolResultMaxBytes int
	HighWatermark      float64
	LowWatermark       float64
	KeepTurns          int
	KeepThinkTurns     int

	// Sectool
	ProxyPort int
	MCPPort   int

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
)

// Parse parses args against fs and returns a populated Config.
func Parse(fs *flag.FlagSet, args []string) (*Config, error) {
	c := &Config{}

	fs.StringVar(&c.BaseURL, "base-url", "", "OpenAI-compatible base URL")
	fs.StringVar(&c.APIKey, "api-key", "", "optional API key")
	fs.StringVar(&c.Model, "model", "", "main model ID (workers, verifier, director, summarizer)")
	fs.StringVar(&c.LogModel, "log-model", "", "model ID for narrator + candidate dedup; defaults to --model")
	fs.IntVar(&c.AgentPoolSize, "agent-pool-size", 4, "concurrent model request bound (shared pool)")

	fs.IntVar(&c.MaxContext, "max-context", 32768, "main-model context window (tokens)")
	fs.IntVar(&c.LogMaxContext, "log-max-context", 0, "log-model context window; 0 inherits --max-context")
	fs.IntVar(&c.ToolResultMaxBytes, "tool-result-max-bytes", 8192, "per-tool-result truncation cap")
	fs.Float64Var(&c.HighWatermark, "compaction-high-watermark", 0.80, "compaction trigger fraction")
	fs.Float64Var(&c.LowWatermark, "compaction-low-watermark", 0.40, "compaction target fraction")
	fs.IntVar(&c.KeepTurns, "compaction-keep-turns", 4, "turns never compacted")
	fs.IntVar(&c.KeepThinkTurns, "keep-think-turns", 0, "assistant messages to preserve <think> blocks on when replaying history (0 = auto: 4 if max-context ≤ 128k, else 8)")

	fs.IntVar(&c.ProxyPort, "proxy-port", 8181, "sectool proxy port")
	fs.IntVar(&c.MCPPort, "mcp-port", 9119, "sectool MCP port")

	fs.StringVar(&c.Prompt, "prompt", "", "initial task prompt (required)")
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
	c.MaxWorkers = min(max(c.MaxWorkers, MinWorkers), MaxWorkers)
	c.AutonomousBudget = min(max(c.AutonomousBudget, 1), MaxAutonomousBudget)
	if c.LogModel == "" {
		c.LogModel = c.Model
	}
	if c.LogMaxContext <= 0 {
		c.LogMaxContext = c.MaxContext
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
