package orchestrator

// defaultAutonomousBudget is the default per-iteration autonomous-run budget.
const defaultAutonomousBudget = 8

// maxAutonomousBudget caps decide_worker's autonomous_budget at the tool boundary.
const maxAutonomousBudget = 20

// noneSentinel is the placeholder rendered where a list has no items.
const noneSentinel = "(none)"

// decisionDrainMaxRounds caps the per-worker decide_worker drain.
const decisionDrainMaxRounds = 4

// minIterationsForDone is the earliest iteration at which `end_run` is accepted with zero findings filed.
const minIterationsForDone = 5

// maxPendingMerges caps the async merger's queued-or-running merges; excess
// submissions fail fast into the candidate pool. Must stay above the merger
// concurrency capacity (4) so saturation can never stall submissions outright.
const maxPendingMerges = 16
