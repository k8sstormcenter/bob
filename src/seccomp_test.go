package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

func TestArchMapping(t *testing.T) {
	tests := []struct {
		goArch      string
		scmpArch    string
		shouldExist bool
	}{
		{"amd64", "SCMP_ARCH_X86_64", true},
		{"arm64", "SCMP_ARCH_AARCH64", true},
		{"arm", "SCMP_ARCH_ARM", true},
		{"x86", "SCMP_ARCH_X86", true},
		{"i386", "SCMP_ARCH_X86", true},
		{"ppc64le", "SCMP_ARCH_PPC64LE", true},
		{"s390x", "SCMP_ARCH_S390X", true},
		{"riscv64", "SCMP_ARCH_RISCV64", true},
		{"mips", "", false},
	}

	for _, tt := range tests {
		got, ok := archToSeccomp[tt.goArch]
		if ok != tt.shouldExist {
			t.Errorf("archToSeccomp[%q]: exists=%v, want %v", tt.goArch, ok, tt.shouldExist)
		}
		if ok && got != tt.scmpArch {
			t.Errorf("archToSeccomp[%q] = %q, want %q", tt.goArch, got, tt.scmpArch)
		}
	}

	for _, tt := range tests {
		if !tt.shouldExist {
			continue
		}
		rev, ok := seccompToArch[tt.scmpArch]
		if !ok {
			t.Errorf("seccompToArch[%q] not found", tt.scmpArch)
		}
		if _, ok := archToSeccomp[rev]; !ok {
			t.Errorf("seccompToArch[%q] = %q, which is not in archToSeccomp", tt.scmpArch, rev)
		}
	}
}

func TestWriteSeccompProfile(t *testing.T) {
	profile := &ApplicationProfile{
		Spec: ApplicationProfileSpec{
			Architectures: []string{"amd64"},
			Containers: []ContainerProfile{
				{
					Name:         "test-container",
					Syscalls:     []string{"write", "read", "unknown", "accept4", "read"},
					Capabilities: []string{"NET_ADMIN"},
					Execs:        []Exec{{Path: "/bin/sh"}},
					Opens:        []Open{{Path: "/etc/hosts", Flags: []string{"O_RDONLY"}}},
					Endpoints:    []Endpoint{{Direction: "inbound", Endpoint: "10.0.0.1:80"}},
				},
			},
		},
	}

	outFile := filepath.Join(t.TempDir(), "test-seccomp.json")
	err := writeSeccompProfile(outFile, nil, profile)
	if err != nil {
		t.Fatalf("writeSeccompProfile failed: %v", err)
	}

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("reading output: %v", err)
	}

	var sp SeccompProfile
	if err := json.Unmarshal(data, &sp); err != nil {
		t.Fatalf("parsing output JSON: %v", err)
	}

	if sp.DefaultAction != "SCMP_ACT_ERRNO" {
		t.Errorf("defaultAction = %q, want SCMP_ACT_ERRNO", sp.DefaultAction)
	}

	if len(sp.Architectures) != 1 || sp.Architectures[0] != "SCMP_ARCH_X86_64" {
		t.Errorf("architectures = %v, want [SCMP_ARCH_X86_64]", sp.Architectures)
	}

	if len(sp.Syscalls) != 1 {
		t.Fatalf("expected 1 syscall rule, got %d", len(sp.Syscalls))
	}

	rule := sp.Syscalls[0]
	if rule.Action != "SCMP_ACT_ALLOW" {
		t.Errorf("rule action = %q, want SCMP_ACT_ALLOW", rule.Action)
	}

	expected := []string{"accept4", "read", "write"}
	if !reflect.DeepEqual(rule.Names, expected) {
		t.Errorf("syscall names = %v, want %v", rule.Names, expected)
	}
}

func TestWriteSeccompMultiContainer(t *testing.T) {
	profile := &ApplicationProfile{
		Spec: ApplicationProfileSpec{
			Containers: []ContainerProfile{
				{Name: "web", Syscalls: []string{"read", "write"}},
				{Name: "sidecar", Syscalls: []string{"read", "epoll_wait"}},
			},
		},
	}

	dir := t.TempDir()
	outFile := filepath.Join(dir, "profile.json")
	err := writeSeccompProfile(outFile, nil, profile)
	if err != nil {
		t.Fatalf("writeSeccompProfile failed: %v", err)
	}

	for _, name := range []string{"profile-web.json", "profile-sidecar.json"} {
		path := filepath.Join(dir, name)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			t.Errorf("expected file %s to exist", path)
		}
	}

	if _, err := os.Stat(outFile); !os.IsNotExist(err) {
		t.Errorf("expected %s to NOT exist in multi-container mode", outFile)
	}
}

func TestParseSeccompProfile(t *testing.T) {
	sp := SeccompProfile{
		DefaultAction: "SCMP_ACT_ERRNO",
		Architectures: []string{"SCMP_ARCH_X86_64", "SCMP_ARCH_AARCH64"},
		Syscalls: []SeccompRule{
			{Names: []string{"read", "write", "close"}, Action: "SCMP_ACT_ALLOW"},
			{Names: []string{"mount"}, Action: "SCMP_ACT_LOG"},
		},
	}

	dir := t.TempDir()
	inFile := filepath.Join(dir, "test-input.json")
	data, _ := json.Marshal(sp)
	os.WriteFile(inFile, data, 0644)

	profile, err := parseSeccompProfile(inFile)
	if err != nil {
		t.Fatalf("parseSeccompProfile failed: %v", err)
	}

	if profile.APIVersion != "spdx.softwarecomposition.kubescape.io/v1beta1" {
		t.Errorf("apiVersion = %q, want kubescape CRD version", profile.APIVersion)
	}
	if profile.Kind != "ApplicationProfile" {
		t.Errorf("kind = %q, want ApplicationProfile", profile.Kind)
	}

	if len(profile.Spec.Containers) != 1 {
		t.Fatalf("expected 1 container, got %d", len(profile.Spec.Containers))
	}

	container := profile.Spec.Containers[0]
	expectedSyscalls := []string{"close", "read", "write"}
	if !reflect.DeepEqual(container.Syscalls, expectedSyscalls) {
		t.Errorf("syscalls = %v, want %v", container.Syscalls, expectedSyscalls)
	}

	for _, sc := range container.Syscalls {
		if sc == "mount" {
			t.Error("mount should not be included (non-ALLOW action)")
		}
	}

	expectedArchs := []string{"amd64", "arm64"}
	sort.Strings(profile.Spec.Architectures)
	if !reflect.DeepEqual(profile.Spec.Architectures, expectedArchs) {
		t.Errorf("architectures = %v, want %v", profile.Spec.Architectures, expectedArchs)
	}

	if container.Name != "test-input" {
		t.Errorf("container name = %q, want %q", container.Name, "test-input")
	}
}

func TestRoundTrip(t *testing.T) {
	profile, err := parseKubescapeProfile("../example/redis-profile.yaml")
	if err != nil {
		t.Fatalf("parsing redis profile: %v", err)
	}

	dir := t.TempDir()
	seccompFile := filepath.Join(dir, "redis-seccomp.json")

	err = writeSeccompProfile(seccompFile, nil, profile)
	if err != nil {
		t.Fatalf("writing seccomp: %v", err)
	}

	roundTripped, err := parseSeccompProfile(seccompFile)
	if err != nil {
		t.Fatalf("parsing seccomp: %v", err)
	}

	var originalSyscalls []string
	for _, sc := range profile.Spec.Containers[0].Syscalls {
		if sc != "unknown" {
			originalSyscalls = append(originalSyscalls, sc)
		}
	}
	sort.Strings(originalSyscalls)
	originalSyscalls = unique(originalSyscalls)

	rtSyscalls := roundTripped.Spec.Containers[0].Syscalls
	sort.Strings(rtSyscalls)

	if !reflect.DeepEqual(rtSyscalls, originalSyscalls) {
		t.Errorf("round-trip syscalls don't match.\ngot:  %v\nwant: %v", rtSyscalls, originalSyscalls)
	}
}
