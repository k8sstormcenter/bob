package main

import (
	"flag"
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

// Supported formats
type ProfileFormat string

const (
	FormatKubescape ProfileFormat = "kubescape"
	FormatNeuVector ProfileFormat = "neuvector"
	FormatAppArmor  ProfileFormat = "apparmor"
	FormatSeccomp   ProfileFormat = "seccomp"
)

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

// TODO: make this list complete
// Maps syscall name to the minimum kernel version
// Rationale: If youre going from a higher kernel version to a lower one, where syscalls dont exist yet, your profile likely wont work (in extreme cases, your app wont work)
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
}

var capabilityKernelVersions = map[string]string{
	"setpcap":   "2.6.24",
	"sys_admin": "2.2",
}

// a table of syscalls forbidden by the Defaults of different Runtimes
// TODO: fill this out for crio containerd and moby
var seccompDefault = map[string]string{
	"containerd": "umount, clone",
}

var (
	inputFile    string
	outputFile   string
	inputFormat  string
	outputFormat string
	inputKernel  string
	outputKernel string
	inputK8s     string
	outputK8s    string
	configFile   string
)

func init() {
	flag.StringVar(&inputFile, "input", "", "Input profile file")
	flag.StringVar(&outputFile, "output", "", "Output profile file")
	flag.StringVar(&inputFormat, "input-format", "kubescape", "Input format: kubescape|neuvector|apparmor|seccomp")
	flag.StringVar(&outputFormat, "output-format", "kubescape", "Output format: kubescape|neuvector|apparmor|seccomp")
	flag.StringVar(&inputKernel, "input-kernel", "", "Input kernel version (e.g. 5.15.0)")
	flag.StringVar(&outputKernel, "output-kernel", "", "Output kernel version (e.g. 6.1.0)")
	flag.StringVar(&inputK8s, "input-k8s", "", "Input Kubernetes version (e.g. 1.28.0)")
	flag.StringVar(&outputK8s, "output-k8s", "", "Output Kubernetes version (e.g. 1.30.0)")
	flag.StringVar(&configFile, "config", "", "Input config file")
}

func main() {
	flag.Parse()
	if inputFile == "" || outputFile == "" {
		fmt.Println("Usage: translate-profile --input <file> --output <file> [--input-format ...] [--output-format ...] [--input-kernel ...] [--output-kernel ...] [--input-k8s ...] [--output-k8s ...]")
		os.Exit(1)
	}

	// 1. Parse input profile
	var profile *ApplicationProfile
	var err error
	switch ProfileFormat(strings.ToLower(inputFormat)) {
	case FormatKubescape:
		profile, err = parseKubescapeProfile(inputFile)
	case FormatNeuVector:
		profile, err = parseNeuVectorProfile(inputFile)
	case FormatAppArmor:
		profile, err = parseAppArmorProfile(inputFile)
	case FormatSeccomp:
		profile, err = parseSeccompProfile(inputFile)
	default:
		log.Fatalf("Unsupported input format: %s", inputFormat)
	}
	if err != nil {
		log.Fatalf("Error parsing input: %v", err)
	}

	config, err := parseConfig(configFile)
	if err != nil {
		log.Fatalf("Error parsing config: %v", err)
	}

	// 2. Optionally, normalize/translate profile for kernel/k8s version
	if outputKernel != "" {
		for i := range profile.Spec.Containers {
			profile.Spec.Containers[i].Syscalls = correctSyscalls(profile.Spec.Containers[i].Syscalls, outputKernel)
		}
	}
	// 3. Write output in requested format
	switch ProfileFormat(strings.ToLower(outputFormat)) {
	case FormatKubescape:
		//templatedProfile, err := templateKubescapeProfile(profile, config, outputKernel) // TODO find toggle to switch between HELM and other template engines
		if err != nil {
			log.Fatalf("Error templating profile: %v", err)
		}
		err = writeKubescapeProfile(outputFile, config, profile)
	case FormatNeuVector:
		err = writeNeuVectorProfile(outputFile, config, profile)
	case FormatAppArmor:
		err = writeAppArmorProfile(outputFile, config, profile)
	case FormatSeccomp:
		err = writeSeccompProfile(outputFile, config, profile)
	default:
		log.Fatalf("Unsupported output format: %s", outputFormat)
	}
	if err != nil {
		log.Fatalf("Error writing output: %v", err)
	}

	fmt.Printf("Successfully translated profile from %s to %s: %s\n", inputFormat, outputFormat, outputFile)
}

func parseKubescapeProfile(filename string) (*ApplicationProfile, error) {
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

func writeKubescapeProfile(filename string, config *TemplateConfig, profile *ApplicationProfile) error {
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

func templateKubescapeProfile(profile *ApplicationProfile, config *TemplateConfig, targetKernel string) (*ApplicationProfile, error) {
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

func parseNeuVectorProfile(filename string) (*ApplicationProfile, error) {
	// TODO: Implement NeuVector JSON/YAML parsing and mapping to ApplicationProfile
	return nil, fmt.Errorf("NeuVector parsing not implemented")
}

func writeNeuVectorProfile(filename string, config *TemplateConfig, profile *ApplicationProfile) error {
	// TODO: Implement serialization to NeuVector format
	return fmt.Errorf("NeuVector output not implemented")
}

func parseAppArmorProfile(filename string) (*ApplicationProfile, error) {
	// TODO: Implement AppArmor parsing and mapping to ApplicationProfile
	return nil, fmt.Errorf("AppArmor parsing not implemented")
}

func writeAppArmorProfile(filename string, config *TemplateConfig, profile *ApplicationProfile) error {
	// TODO: Implement serialization to AppArmor format
	return fmt.Errorf("AppArmor output not implemented")
}

func parseSeccompProfile(filename string) (*ApplicationProfile, error) {
	// TODO: Implement Seccomp parsing and mapping to ApplicationProfile
	return nil, fmt.Errorf("Seccomp parsing not implemented")
}
func writeSeccompProfile(filename string, config *TemplateConfig, profile *ApplicationProfile) error {
	// TODO: Implement serialization to Seccomp format
	return fmt.Errorf("Seccomp output not implemented")
}
