package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type SeccompProfile struct {
	DefaultAction string        `json:"defaultAction"`
	Architectures []string      `json:"architectures,omitempty"`
	Syscalls      []SeccompRule `json:"syscalls,omitempty"`
}

type SeccompRule struct {
	Names  []string `json:"names"`
	Action string   `json:"action"`
}

var archToSeccomp = map[string]string{
	"amd64":   "SCMP_ARCH_X86_64",
	"arm64":   "SCMP_ARCH_AARCH64",
	"arm":     "SCMP_ARCH_ARM",
	"x86":     "SCMP_ARCH_X86",
	"i386":    "SCMP_ARCH_X86",
	"ppc64le": "SCMP_ARCH_PPC64LE",
	"s390x":   "SCMP_ARCH_S390X",
	"riscv64": "SCMP_ARCH_RISCV64",
}

var seccompToArch = map[string]string{
	"SCMP_ARCH_X86_64":  "amd64",
	"SCMP_ARCH_AARCH64": "arm64",
	"SCMP_ARCH_ARM":     "arm",
	"SCMP_ARCH_X86":     "x86",
	"SCMP_ARCH_PPC64LE": "ppc64le",
	"SCMP_ARCH_S390X":   "s390x",
	"SCMP_ARCH_RISCV64": "riscv64",
}

func writeSeccompProfile(filename string, config *TemplateConfig, profile *ApplicationProfile) error {
	containers := append(profile.Spec.Containers, profile.Spec.InitContainers...)
	if len(containers) == 0 {
		return fmt.Errorf("profile has no containers")
	}

	multiContainer := len(containers) > 1

	for _, container := range containers {
		sp := SeccompProfile{
			DefaultAction: "SCMP_ACT_ERRNO",
		}

		for _, arch := range profile.Spec.Architectures {
			if scmpArch, ok := archToSeccomp[arch]; ok {
				sp.Architectures = append(sp.Architectures, scmpArch)
			} else {
				log.Printf("Warning: Unknown architecture %q, skipping", arch)
			}
		}

		var syscalls []string
		for _, sCall := range container.Syscalls {
			if sCall == "unknown" {
				log.Printf("Info: Filtering out \"unknown\" syscall (Kubescape sentinel value)")
				continue
			}
			syscalls = append(syscalls, sCall)
		}
		sort.Strings(syscalls)
		syscalls = unique(syscalls)

		if len(syscalls) > 0 {
			sp.Syscalls = []SeccompRule{
				{
					Names:  syscalls,
					Action: "SCMP_ACT_ALLOW",
				},
			}
		}

		if len(container.Capabilities) > 0 {
			log.Printf("Info: Dropping %d capabilities — seccomp profiles don't support capability enforcement", len(container.Capabilities))
		}
		if len(container.Endpoints) > 0 {
			log.Printf("Info: Dropping %d endpoints — seccomp profiles don't support network endpoint definitions", len(container.Endpoints))
		}
		if len(container.Execs) > 0 {
			log.Printf("Info: Dropping %d execs — seccomp profiles don't support exec allowlists", len(container.Execs))
		}
		if len(container.Opens) > 0 {
			log.Printf("Info: Dropping %d opens — seccomp profiles don't support file open allowlists", len(container.Opens))
		}

		data, err := json.MarshalIndent(sp, "", "  ")
		if err != nil {
			return fmt.Errorf("marshaling seccomp profile for container %q: %w", container.Name, err)
		}
		data = append(data, '\n')

		outPath := filename
		if multiContainer {
			ext := filepath.Ext(filename)
			stem := strings.TrimSuffix(filename, ext)
			outPath = fmt.Sprintf("%s-%s%s", stem, container.Name, ext)
		}

		dir := filepath.Dir(outPath)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("creating output directory: %w", err)
		}

		if err := os.WriteFile(outPath, data, 0644); err != nil {
			return fmt.Errorf("writing seccomp profile to %s: %w", outPath, err)
		}

		log.Printf("Wrote seccomp profile for container %q to %s", container.Name, outPath)
	}

	return nil
}

func parseSeccompProfile(filename string) (*ApplicationProfile, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var sp SeccompProfile
	if err := json.Unmarshal(data, &sp); err != nil {
		return nil, fmt.Errorf("parsing seccomp JSON: %w", err)
	}

	var syscalls []string
	for _, rule := range sp.Syscalls {
		if rule.Action == "SCMP_ACT_ALLOW" {
			syscalls = append(syscalls, rule.Names...)
		} else {
			log.Printf("Warning: Skipping seccomp rule with action %q (only SCMP_ACT_ALLOW is mapped)", rule.Action)
		}
	}
	sort.Strings(syscalls)
	syscalls = unique(syscalls)

	var archs []string
	for _, scmpArch := range sp.Architectures {
		if arch, ok := seccompToArch[scmpArch]; ok {
			archs = append(archs, arch)
		} else {
			log.Printf("Warning: Unknown seccomp architecture %q, skipping", scmpArch)
		}
	}

	// Derive container name from filename
	base := filepath.Base(filename)
	containerName := strings.TrimSuffix(base, filepath.Ext(base))

	profile := &ApplicationProfile{
		APIVersion: "spdx.softwarecomposition.kubescape.io/v1beta1",
		Kind:       "ApplicationProfile",
		Metadata: Metadata{
			Name: containerName,
		},
		Spec: ApplicationProfileSpec{
			Architectures: archs,
			Containers: []ContainerProfile{
				{
					Name:     containerName,
					Syscalls: syscalls,
				},
			},
		},
	}

	return profile, nil
}
