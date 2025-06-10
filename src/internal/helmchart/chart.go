package helmchart

import (
	"os"

	"gopkg.in/yaml.v3"
)

// Chart represents the structure of a Chart.yaml file.
type Chart struct {
	APIVersion  string `yaml:"apiVersion"`
	Name        string `yaml:"name"`
	Version     string `yaml:"version"`
	Description string `yaml:"description,omitempty"`
	// Add other fields as needed
}

// ParseChartYaml reads and parses a Chart.yaml file.
func ParseChartYaml(filePath string) (*Chart, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var chart Chart
	if err := yaml.Unmarshal(data, &chart); err != nil {
		return nil, err
	}

	return &chart, nil
}