// Package playbook defines and executes attack playbooks: declarative,
// multi-step adversary campaigns against a target.
package playbook

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Playbook is a reusable attack campaign: an ordered chain of steps,
// each a recon, exploit, or verification action, executed against a
// target in a controlled environment.
type Playbook struct {
	APIVersion   string         `yaml:"apiVersion"`
	Kind         string         `yaml:"kind"`
	Name         string         `yaml:"name"`
	Description  string         `yaml:"description"`
	Target       TargetSelector `yaml:"target"`
	Steps        []Step         `yaml:"steps"`
	Verification []Verification `yaml:"verification"`
}

// TargetSelector constrains what kind of target a playbook applies to.
type TargetSelector struct {
	ChainTypes []string `yaml:"chainTypes"`
	Layers     []string `yaml:"layers"`
}

// Step is a single action in a campaign.
type Step struct {
	ID           string  `yaml:"id"`
	Name         string  `yaml:"name"`
	Tactic       string  `yaml:"tactic"` // setup | discover | exploit | verify | cleanup
	Precondition string  `yaml:"precondition"`
	Run          RunSpec `yaml:"run"`
}

// RunSpec specifies how a step executes.
type RunSpec struct {
	// Type is one of:
	//   engine  — run a BlockTack engine binary (engine-evm, ...) with a JSON job
	//   adapter — run a registered analysis adapter (slither, ...)
	//   shell   — run an external command (anvil, cast, forge, ...)
	//   manual  — a human-directed action; recorded, not executed
	Type    string         `yaml:"type"`
	Engine  string         `yaml:"engine"`  // engine step: binary name, e.g. blocktack-evm
	Adapter string         `yaml:"adapter"` // adapter step: registry name, e.g. slither
	Action  string         `yaml:"action"`  // engine step: action id, e.g. map-oracles
	Command string         `yaml:"command"` // shell step: executable
	Args    []string       `yaml:"args"`    // shell step: arguments (${ENV} expanded)
	Options map[string]any `yaml:"options"` // engine/adapter step: free-form options
	Note    string         `yaml:"note"`    // manual step: instructions
	// Background runs a shell step without waiting for it (e.g. anvil).
	Background bool `yaml:"background"`
}

// Verification states what a successful campaign must demonstrate.
type Verification struct {
	ID      string `yaml:"id"`
	Expects string `yaml:"expects"`
}

// Load reads and validates a playbook YAML file.
func Load(path string) (*Playbook, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read playbook: %w", err)
	}
	var pb Playbook
	if err := yaml.Unmarshal(data, &pb); err != nil {
		return nil, fmt.Errorf("parse playbook %s: %w", path, err)
	}
	if pb.Name == "" {
		return nil, fmt.Errorf("playbook %s: missing required field `name`", path)
	}
	if len(pb.Steps) == 0 {
		return nil, fmt.Errorf("playbook %s: no steps defined", path)
	}
	seen := map[string]bool{}
	for i, s := range pb.Steps {
		if s.ID == "" {
			return nil, fmt.Errorf("playbook %s: step %d missing `id`", path, i+1)
		}
		if seen[s.ID] {
			return nil, fmt.Errorf("playbook %s: duplicate step id %q", path, s.ID)
		}
		seen[s.ID] = true
		if s.Run.Type == "" {
			pb.Steps[i].Run.Type = "manual"
		}
	}
	return &pb, nil
}
