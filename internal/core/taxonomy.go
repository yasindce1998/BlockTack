package core

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// Taxonomy is the BlockTack attack-surface matrix: every layer of a
// blockchain system and the weakness classes within it. It is the shared
// vocabulary for findings, playbooks, and reports.
type Taxonomy struct {
	Version int        `yaml:"version"`
	Layers  []TaxLayer `yaml:"layers"`
}

// TaxLayer is one layer of the stack (L0..L5).
type TaxLayer struct {
	ID          string     `yaml:"id"`
	Name        string     `yaml:"name"`
	Description string     `yaml:"description"`
	Weaknesses  []Weakness `yaml:"weaknesses"`
}

// Weakness is a vulnerability class within a layer, identified by a
// stable ID of the form BTV-L<layer>-<nnn>.
type Weakness struct {
	ID          string   `yaml:"id"`
	Name        string   `yaml:"name"`
	Description string   `yaml:"description"`
	Tags        []string `yaml:"tags"`
}

// LoadTaxonomy reads the taxonomy YAML file.
func LoadTaxonomy(path string) (*Taxonomy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read taxonomy: %w", err)
	}
	var tx Taxonomy
	if err := yaml.Unmarshal(data, &tx); err != nil {
		return nil, fmt.Errorf("parse taxonomy %s: %w", path, err)
	}
	if len(tx.Layers) == 0 {
		return nil, fmt.Errorf("taxonomy %s: no layers defined", path)
	}
	return &tx, nil
}

// Weakness looks up a weakness by its taxonomy ID.
func (tx *Taxonomy) Weakness(id string) (Weakness, bool) {
	for _, l := range tx.Layers {
		for _, w := range l.Weaknesses {
			if w.ID == id {
				return w, true
			}
		}
	}
	return Weakness{}, false
}

// Layer returns the layer with the given ID (e.g. "L2").
func (tx *Taxonomy) Layer(id string) (TaxLayer, bool) {
	for _, l := range tx.Layers {
		if l.ID == id {
			return l, true
		}
	}
	return TaxLayer{}, false
}
