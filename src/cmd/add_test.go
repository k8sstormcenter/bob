package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/k8sstormcenter/bobctl/src/internal/helmchart" 
	"github.com/k8sstormcenter/bobctl/src/internal/helmtest"  
	"github.com/spf13/cobra"
)

var (
	chartPath string
	testName  string
)

var addTestCmd = &cobra.Command{
	Use:   "add-test",
	Short: "Adds a unit test file to an existing Helm chart",
	Long: `Adds a basic unit test file to a specified Helm chart.
The test file is structured for use with the 'helm-unittest' plugin.
It will create a 'tests/' directory in the chart if it doesn't exist.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// 1. Validate chartPath
		if chartPath == "" {
			return fmt.Errorf("--chart-path is required")
		}

		chartInfo, err := os.Stat(chartPath)
		if os.IsNotExist(err) {
			return fmt.Errorf("chart path does not exist: %s", chartPath)
		}
		if !chartInfo.IsDir() {
			return fmt.Errorf("chart path is not a directory: %s", chartPath)
		}

		chartYamlPath := filepath.Join(chartPath, "Chart.yaml")
		if _, err := os.Stat(chartYamlPath); os.IsNotExist(err) {
			return fmt.Errorf("Chart.yaml not found in %s. Is this a valid Helm chart directory?", chartPath)
		}

		// 2. Parse Chart.yaml to get chart name
		parsedChart, err := helmchart.ParseChartYaml(chartYamlPath)
		if err != nil {
			return fmt.Errorf("failed to parse Chart.yaml: %w", err)
		}
		fmt.Printf("Found chart: %s, Version: %s\n", parsedChart.Name, parsedChart.Version)

		// 3. Determine test name
		actualTestName := testName
		if actualTestName == "" {
			actualTestName = fmt.Sprintf("%s-deployment", parsedChart.Name) // Default test name
		}
		// Ensure it ends with _test.yaml for helm-unittest convention
		if !strings.HasSuffix(actualTestName, "_test") {
			actualTestName = actualTestName + "_test"
		}
		testFileName := actualTestName + ".yaml"

		// 4. Create tests directory if it doesn't exist
		testsDirPath := filepath.Join(chartPath, "tests")
		if err := os.MkdirAll(testsDirPath, 0755); err != nil {
			return fmt.Errorf("failed to create tests directory %s: %w", testsDirPath, err)
		}
		fmt.Printf("Ensured 'tests' directory exists at: %s\n", testsDirPath)

		// 5. Create and write the test file
		testFilePath := filepath.Join(testsDirPath, testFileName)
		if _, err := os.Stat(testFilePath); err == nil {
			return fmt.Errorf("test file %s already exists", testFilePath)
		}

		testContent, err := helmtest.GenerateTestFileContent(helmtest.TestData{
			SuiteName: strings.ReplaceAll(actualTestName, "_test", " tests"),
			ChartName: parsedChart.Name,
			// You can add more fields here to pass to the template, e.g., specific template files
			TestTemplates: []string{"templates/deployment.yaml"}, // Default assumption
		})
		if err != nil {
			return fmt.Errorf("failed to generate test file content: %w", err)
		}

		if err := os.WriteFile(testFilePath, []byte(testContent), 0644); err != nil {
			return fmt.Errorf("failed to write test file %s: %w", testFilePath, err)
		}

		fmt.Printf("Successfully created test file: %s\n", testFilePath)
		fmt.Println("You can now run your tests, typically using a plugin like 'helm-unittest':")
		fmt.Printf("  helm unittest %s\n", chartPath)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(addTestCmd)
	addTestCmd.Flags().StringVarP(&chartPath, "chart-path", "c", "", "Path to the Helm chart directory (required)")
	addTestCmd.Flags().StringVarP(&testName, "test-name", "n", "", "Name for the test suite (e.g., myfeature-test). Defaults to <chart-name>-deployment_test")
	// Mark chart-path as required, though we also check it in RunE for better error message
	// addTestCmd.MarkFlagRequired("chart-path") // Cobra can do this, but manual check gives more context
}