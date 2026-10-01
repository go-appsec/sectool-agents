// Package state persists agent-wide state across runs.
//
// The on-disk schema is a single JSON object whose top-level fields are
// per-feature sub-structs with `omitempty` JSON tags, so adding a new
// kind of state is a one-field change. Today the only field is the
// best-effort sectool version-check cache.
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/go-appsec/sectool-agents/secagent/util"
)

// State is the full on-disk shape. New per-feature fields go here.
type State struct {
	SectoolVersionCheck *SectoolVersionCheckEntry `json:"sectool_version_check,omitempty"`
}

// SectoolVersionCheckEntry caches the staleness-check outcome.
// Status is "ok" or "failed"; LatestVersion is only set when Status == "ok".
type SectoolVersionCheckEntry struct {
	LatestVersion string `json:"latest_version,omitempty"`
	CheckedAt     int64  `json:"checked_at"`
	Status        string `json:"status"`
}

// Load returns the state at path; missing or corrupt files yield an empty State without error.
func Load(path string) (*State, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &State{}, nil
		}
		return nil, fmt.Errorf("read state: %w", err)
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		// corrupt -> reset rather than propagate
		return &State{}, nil
	}
	return &s, nil
}

// Save writes s to path atomically via tmp+rename.
func Save(path string, s *State) error {
	data, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}
	if err := util.WriteFileAtomic(path, data, 0o644); err != nil {
		return fmt.Errorf("save state: %w", err)
	}
	return nil
}
