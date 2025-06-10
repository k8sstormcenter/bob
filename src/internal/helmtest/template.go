package helmtest

import (
	"bytes"
	"text/template"
)

const defaultTestTemplate = `suite: {{ .SuiteName }}
templates:
{{- range .TestTemplates }}
  - "{{ . }}"
{{- end }}
tests:
  - it: should render the {{ .ChartName }} deployment correctly
    # Example: Set values for your test
    # set:
    #   replicaCount: 2
    #   image.tag: "latest"
    asserts:
      - isKind:
          of: Deployment
      - matchRegex: # Assumes release name is prefixed to the chart name for the deployment
          path: metadata.name
          pattern: "-{{ .ChartName }}$"
      - equal:
          path: spec.template.spec.containers[0].name
          value: {{ .ChartName }} # A common convention, adjust if your chart differs
`

// TestData holds data for rendering the test template.
type TestData struct {
	SuiteName     string
	ChartName     string
	TestTemplates []string // List of template files to include in the test
}

// GenerateTestFileContent creates the content for a Helm unit test file.
func GenerateTestFileContent(data TestData) (string, error) {
	tmpl, err := template.New("helmTest").Parse(defaultTestTemplate)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", err
	}

	return buf.String(), nil
}