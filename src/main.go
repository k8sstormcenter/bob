package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/mod/semver"
	"gopkg.in/yaml.v3"
)

// --- 1. Structs for ApplicationProfile YAML ---

type ApplicationProfile struct {
	APIVersion string                 `yaml:"apiVersion"`
	Kind       string                 `yaml:"kind"`
	Metadata   Metadata               `yaml:"metadata"`
	Spec       ApplicationProfileSpec `yaml:"spec"`
	Status     map[string]interface{} `yaml:"status,omitempty"`
}

type Metadata struct {
	Name        string            `yaml:"name"`
	Namespace   string            `yaml:"namespace"`
	Annotations map[string]string `yaml:"annotations"`
	Labels      map[string]string `yaml:"labels"`
}

type ApplicationProfileSpec struct {
	Architectures  []string           `yaml:"architectures"`
	Containers     []ContainerProfile `yaml:"containers"`
	InitContainers []ContainerProfile `yaml:"initContainers,omitempty"`
}

type ContainerProfile struct {
	Name         string     `yaml:"name"`
	ImageTag     string     `yaml:"imageTag"`
	Capabilities []string   `yaml:"capabilities,omitempty"`
	Endpoints    []Endpoint `yaml:"endpoints,omitempty"`
	Execs        []Exec     `yaml:"execs,omitempty"`
	Opens        []Open     `yaml:"opens,omitempty"`
	Syscalls     []string   `yaml:"syscalls,omitempty"`
}

type Endpoint struct {
	Direction string              `yaml:"direction"`
	Endpoint  string              `yaml:"endpoint"`
	Headers   map[string][]string `yaml:"headers,omitempty"`
	Internal  bool                `yaml:"internal"`
	Methods   []string            `yaml:"methods,omitempty"`
}

type Exec struct {
	Path string   `yaml:"path"`
	Args []string `yaml:"args"`
}

type Open struct {
	Path  string   `yaml:"path"`
	Flags []string `yaml:"flags"`
}

// --- 2. Structs for Templating Configuration ---

type TemplateConfig struct {
	WorkloadName string            `yaml:"workloadName"`
	Namespace    string            `yaml:"namespace"`
	TemplateHash string            `yaml:"templateHash"`
	IPs          map[string]string `yaml:"ips"`
	Ports        map[string]string `yaml:"ports"`
}

// --- 3. Syscall to Kernel Version Database ---

// A small, illustrative database. A real tool would have a more extensive list.
// Maps syscall name to the minimum kernel version that supports it.
var syscallKernelVersions = map[string]string{
	"accept4":      "2.6.28",
	"clone3":       "5.3",
	"close_range":  "5.9",
	"epoll_pwait2": "5.19",
	"faccessat2":   "5.8",
	"fsconfig":     "5.12",
	"fsmount":      "5.12",
	"fsopen":       "5.12",
	"futex_waitv":  "5.16",
	"open_tree":    "5.12",
	"openat2":      "5.6",
	"rseq":         "4.18",
	"setns":        "3.0",
	"unshare":      "2.6.16",
	"setpcap":      "2.6.24", // Not a syscall, but capability example
	"sys_admin":    "2.2",    // Not a syscall, but capability example
}

func main() {
	if len(os.Args) != 5 {
		fmt.Println("Usage: go run main.go <input-profile.yaml> <template-config.yaml> <target-kernel-version> <output-helm-template.yaml>")
		os.Exit(1)
	}

	inputFile := os.Args[1]
	configFile := os.Args[2]
	targetKernel := os.Args[3]
	outputFile := os.Args[4]

	// --- Parse Inputs ---
	profile, err := parseProfile(inputFile)
	if err != nil {
		log.Fatalf("Error parsing profile: %v", err)
	}

	config, err := parseConfig(configFile)
	if err != nil {
		log.Fatalf("Error parsing config: %v", err)
	}

	// --- Template the Profile ---
	templatedProfile, err := templateProfile(profile, config, targetKernel)
	if err != nil {
		log.Fatalf("Error templating profile: %v", err)
	}

	// --- Write Output ---
	err = writeProfile(outputFile, templatedProfile)
	if err != nil {
		log.Fatalf("Error writing output profile: %v", err)
	}

	fmt.Printf("Successfully generated Helm template at %s\n", outputFile)
}

func parseProfile(filename string) (*ApplicationProfile, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var profile ApplicationProfile
	err = yaml.Unmarshal(data, &profile)
	if err != nil {
		return nil, err
	}
	return &profile, nil
}

func parseConfig(filename string) (*TemplateConfig, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var config TemplateConfig
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return nil, err
	}
	return &config, nil
}

func writeProfile(filename string, profile *ApplicationProfile) error {
	data, err := yaml.Marshal(profile)
	if err != nil {
		return err
	}

	// Create directory if it doesn't exist
	dir := filepath.Dir(filename)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	return os.WriteFile(filename, data, 0644)
}

func templateProfile(profile *ApplicationProfile, config *TemplateConfig, targetKernel string) (*ApplicationProfile, error) {
	// --- Template Metadata ---
	workloadName := profile.Metadata.Labels["kubescape.io/workload-name"]
	templateHash := profile.Metadata.Labels["kubescape.io/instance-template-hash"]
	namespace := profile.Metadata.Namespace

	// Replace name
	profile.Metadata.Name = strings.Replace(profile.Metadata.Name, workloadName, config.WorkloadName, 1)
	profile.Metadata.Name = strings.Replace(profile.Metadata.Name, templateHash, config.TemplateHash, 1)

	// Replace namespace
	profile.Metadata.Namespace = config.Namespace

	// Replace annotations
	for k, v := range profile.Metadata.Annotations {
		v = strings.Replace(v, workloadName, config.WorkloadName, -1)
		v = strings.Replace(v, templateHash, config.TemplateHash, -1)
		v = strings.Replace(v, namespace, config.Namespace, -1)
		profile.Metadata.Annotations[k] = v
	}

	// Replace labels
	for k, v := range profile.Metadata.Labels {
		if v == workloadName {
			profile.Metadata.Labels[k] = config.WorkloadName
		}
		if v == templateHash {
			profile.Metadata.Labels[k] = config.TemplateHash
		}
		if v == namespace {
			profile.Metadata.Labels[k] = config.Namespace
		}
	}

	// --- Template Containers ---
	for i := range profile.Spec.Containers {
		container := &profile.Spec.Containers[i]

		// Template Endpoints
		for j := range container.Endpoints {
			endpoint := &container.Endpoints[j]
			for ip, ipTmpl := range config.IPs {
				endpoint.Endpoint = strings.Replace(endpoint.Endpoint, ip, ipTmpl, -1)
				if hosts, ok := endpoint.Headers["Host"]; ok {
					for k, host := range hosts {
						endpoint.Headers["Host"][k] = strings.Replace(host, ip, ipTmpl, -1)
					}
				}
			}
			for port, portTmpl := range config.Ports {
				endpoint.Endpoint = strings.Replace(endpoint.Endpoint, port, portTmpl, -1)
				if hosts, ok := endpoint.Headers["Host"]; ok {
					for k, host := range hosts {
						endpoint.Headers["Host"][k] = strings.Replace(host, ":"+port, ":"+portTmpl, -1)
					}
				}
			}
		}

		// Correct Syscalls
		container.Syscalls = correctSyscalls(container.Syscalls, targetKernel)
	}

	// (Could do the same for initContainers if needed)

	return profile, nil
}

func correctSyscalls(observedSyscalls []string, targetKernel string) []string {
	if !strings.HasPrefix(targetKernel, "v") {
		targetKernel = "v" + targetKernel
	}

	if !semver.IsValid(targetKernel) {
		log.Printf("Warning: Invalid target kernel version '%s'. Returning original syscall list.", targetKernel)
		return observedSyscalls
	}

	var correctedSyscalls []string
	for _, syscall := range observedSyscalls {
		minVersion, exists := syscallKernelVersions[syscall]
		if !exists {
			// If syscall is not in our DB, assume it's compatible (safe default)
			correctedSyscalls = append(correctedSyscalls, syscall)
			continue
		}

		if !strings.HasPrefix(minVersion, "v") {
			minVersion = "v" + minVersion
		}

		if !semver.IsValid(minVersion) {
			log.Printf("Warning: Invalid syscall version '%s' in database for syscall '%s'. Including it by default.", minVersion, syscall)
			correctedSyscalls = append(correctedSyscalls, syscall)
			continue
		}

		// Compare versions: if targetKernel >= minVersion
		if semver.Compare(targetKernel, minVersion) >= 0 {
			correctedSyscalls = append(correctedSyscalls, syscall)
		} else {
			log.Printf("Info: Removing syscall '%s' as it requires kernel >= %s (target is %s)", syscall, minVersion, targetKernel)
		}
	}

	// Sort and remove duplicates
	sort.Strings(correctedSyscalls)
	return unique(correctedSyscalls)
}

func unique(s []string) []string {
	if len(s) == 0 {
		return s
	}
	keys := make(map[string]bool)
	list := []string{}
	for _, entry := range s {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}

// Helper function to convert string to int, used in older draft
func toInt(s string) int {
	i, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return i
}
