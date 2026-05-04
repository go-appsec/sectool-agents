package orchestrator

// defaultAutonomousBudget is the default per-iteration autonomous-run budget.
const defaultAutonomousBudget = 8

// noneSentinel is the placeholder rendered where a list has no items.
const noneSentinel = "(none)"

// decisionDrainMaxRounds caps the per-worker decide_worker drain.
const decisionDrainMaxRounds = 4

// minIterationsForDone is the earliest iteration at which `end_run` is accepted with zero findings filed.
const minIterationsForDone = 5
