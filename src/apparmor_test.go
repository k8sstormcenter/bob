package main
import (
	"strings"
	"testing"
)

func TestConvertFlagsToAppArmorPermissions (t *testing.T) {

	tests := []struct {
		name string
		flags []string
		want string
	}{
		{"read only", []string{"O_RDONLY"}, "r"},
		{"write only", []string{"O_WRONLY"}, "w"},
		{"read write", []string{"O_RDWR"}, "rw"},
		{"create implies write", []string{"O_CREAT"}, "w"},
		{"truncate implies write", []string{"O_TRUNC"}, "w"},
		{"append implies write", []string{"O_APPEND"}, "w"},
		{"rdonly + cloexec (ignore cloexec)", []string{"O_RDONLY", "O_CLOEXEC"}, "r"},
		{"create + wronly", []string{"O_CREAT", "O_WRONLY"}, "w"},
		{"rdwr + create", []string{"O_RDWR", "O_CREAT"}, "rw"},
		{"empty flags default to r", []string{}, "r"},
		{"unknown flag default to r", []string{"O_NOCTTY"}, "r"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := convertFlagsToAppArmorPermissions(tt.flags)
			if got != tt.want {
				t.Errorf("convertFlagsToAppArmorPermissions(%v) = %v, want %v", tt.flags, got, tt.want)
			}
		})
	}
}

func TestRenderPermissions(t *testing.T) {
	tests := []struct {
		name string
		perms map[rune]bool
		want string
	}{
		{"read only", map[rune]bool{'r': true}, "r"},
		{"write only", map[rune]bool{'w': true}, "w"},
		{"read + write", map[rune]bool{'r': true, 'w': true}, "rw"},
		{"exec + inherit", map[rune]bool{'x': true, 'i': true}, "ix"},
		{"all permissions ordered", map[rune]bool{'r': true, 'w': true, 'i': true, 'x': true, 'm': true, 'k': true, 'l': true}, "rwixmkl"},
		{"out of order still order", map[rune]bool{'x': true, 'r': true}, "rx"},
		{"empty", map[rune]bool{}, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := renderPermissions(tt.perms)
			if got != tt.want {
				t.Errorf("renderPermissions(%v) = %v, want %v", tt.perms, got, tt.want)
			}
		})
	}
}

func TestGetParentDirectory(t *testing.T) {

	tests := []struct {
		name string
		path string
		isDir bool
		want string
	}{
		{"file in dir", "/foo/bar/baz.txt", false, "/foo/bar/"},
		{"file at root", "/foo.conf", false, "/"},
		{"root itself", "/", false, "/"},
		{"dir path", "/foo/bar/", true, "/foo/bar/"},
		{"dir path without trailins slash", "/foo/bar", true, "/foo/bar/"},
		{"nested file", "/foo/bar/baz/acc.log", false, "/foo/bar/baz/"},	
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T){
			got := getParentDirectory(tt.path, tt.isDir)
			if got != tt.want {
				t.Errorf("parentDirectory(%v, %v) = %v, want %v", tt.path, tt.isDir, got, tt.want)
			}
		})
	}
}

func TestConvertExecsToPathRules(t *testing.T) {
	profile := &ApplicationProfile{
		Spec: ApplicationProfileSpec{
			Containers: []ContainerProfile{
				{
					Name: "app",
					Execs: []Exec{
						{Path: "/foo/bar/baz"},
						{Path: "/usr/bin/find"},
						{Path: "./relative-binary"}, // should be skipped
					},
				},
			},
			InitContainers: []ContainerProfile{
				{
					Name: "init",
					Execs: []Exec{
						{Path: "/bin/sh"},
					},
				},
			},
		},
	}
 
	rules := convertExecsToPathRules(profile)
 
	// ./relative-binary must be excluded
	for _, r := range rules {
		if strings.HasPrefix(r.Path, "./") {
			t.Errorf("relative path %q should have been skipped", r.Path)
		}
	}
 
	// All remaining execs must have ix permissions
	for _, r := range rules {
		if !r.Permissions['i'] || !r.Permissions['x'] {
			t.Errorf("exec rule for %q missing ix permissions, got %v", r.Path, r.Permissions)
		}
	}
 
	// init container exec must be included
	paths := make(map[string]bool)
	for _, r := range rules {
		paths[r.Path] = true
	}
	if !paths["/bin/sh"] {
		t.Error("expected /bin/sh from init container, not found")
	}
 
	// 3 execs total: 2 from main container + 1 from init
	if len(rules) != 3 {
		t.Errorf("expected 3 exec rules, got %d", len(rules))
	}
}


func TestConvertOpensToPathRules(t *testing.T) {
	profile := &ApplicationProfile{
		Spec: ApplicationProfileSpec{
			Containers: []ContainerProfile{
				{
					Name: "app",
					Opens: []Open{
						// Read-only: should produce one rule, no parent dir rule
						{Path: "/etc/nginx/nginx.conf", Flags: []string{"O_RDONLY"}},
						// Write: should produce file rule + parent dir rule
						{Path: "/var/log/nginx/access.log", Flags: []string{"O_WRONLY", "O_CREAT", "O_APPEND"}},
						// Directory open: path should get trailing slash
						{Path: "/etc/nginx/conf.d", Flags: []string{"O_RDONLY", "O_DIRECTORY", "O_CLOEXEC"}},
						// Wildcard path: ⋯ should become *
						{Path: "/proc/⋯/maps", Flags: []string{"O_RDONLY"}},
					},
				},
			},
		},
	}
 
	rules := convertOpensToPathRules(profile)
 
	pathPerms := make(map[string]map[rune]bool)
	for _, r := range rules {
		pathPerms[r.Path] = r.Permissions
	}
 
	// Read-only file: just the file with r permission
	if _, ok := pathPerms["/etc/nginx/nginx.conf"]; !ok {
		t.Error("expected rule for /etc/nginx/nginx.conf")
	}
	if !pathPerms["/etc/nginx/nginx.conf"]['r'] {
		t.Error("/etc/nginx/nginx.conf should have r permission")
	}
 
	// Write: both file and parent dir should appear
	if _, ok := pathPerms["/var/log/nginx/access.log"]; !ok {
		t.Error("expected rule for /var/log/nginx/access.log")
	}
	if _, ok := pathPerms["/var/log/nginx/"]; !ok {
		t.Error("expected parent dir rule for /var/log/nginx/ due to write")
	}
 
	// Directory path gets trailing slash
	if _, ok := pathPerms["/etc/nginx/conf.d/"]; !ok {
		t.Error("expected /etc/nginx/conf.d/ with trailing slash for O_DIRECTORY open")
	}
 
	// ⋯ becomes *
	if _, ok := pathPerms["/proc/*/maps"]; !ok {
		t.Error("expected ⋯ to be replaced with * in path /proc/*/maps")
	}
}

func TestMergePathRules(t *testing.T) {
	rules := []MergedPathRule{
		{Path: "/etc/nginx/nginx.conf", Permissions: map[rune]bool{'r': true}},
		{Path: "/etc/nginx/nginx.conf", Permissions: map[rune]bool{'w': true}}, // same path, should merge
		{Path: "/usr/sbin/nginx", Permissions: map[rune]bool{'i': true, 'x': true}},
	}
 
	merged := mergePathRules(rules)
 
	// Should deduplicate to 2 unique paths
	if len(merged) != 2 {
		t.Fatalf("expected 2 merged rules, got %d", len(merged))
	}
 
	// Find the nginx.conf rule
	var confRule *MergedPathRule
	for i := range merged {
		if merged[i].Path == "/etc/nginx/nginx.conf" {
			confRule = &merged[i]
		}
	}
	if confRule == nil {
		t.Fatal("merged rules missing /etc/nginx/nginx.conf")
	}
 
	// Should have both r and w unioned
	if !confRule.Permissions['r'] || !confRule.Permissions['w'] {
		t.Errorf("/etc/nginx/nginx.conf should have rw after merge, got %v", confRule.Permissions)
	}
 
	// Output should be sorted by path
	if merged[0].Path > merged[1].Path {
		t.Errorf("merged rules not sorted: %q > %q", merged[0].Path, merged[1].Path)
	}
}

// capability test
func TestConvertCapToAppArmorRules(t *testing.T) {
	profile := &ApplicationProfile{
		Spec: ApplicationProfileSpec{
			Containers: []ContainerProfile{
				{
					Name: "app",
					Capabilities: []string{"CAP_NET_ADMIN", "CAP_SYS_PTRACE", "CAP_NET_ADMIN"}, // duplicate
				},
			},
			InitContainers: []ContainerProfile{
				{
					Name: "init",
					Capabilities: []string{"CAP_CHOWN"},
				},
			},
		},
	}
 
	rules := convertCapToAppArmorRules(profile)
 
	// Deduplicated: net_admin, sys_ptrace, chown = 3
	if len(rules) != 3 {
		t.Errorf("expected 3 capability rules (deduplicated), got %d: %v", len(rules), rules)
	}
 
	// All should be lowercased and CAP_ prefix stripped
	for _, r := range rules {
		if strings.Contains(r, "CAP_") {
			t.Errorf("capability rule should not contain CAP_ prefix: %q", r)
		}
		lower := strings.ToLower(r)
		if r != lower {
			t.Errorf("capability rule should be lowercase: %q", r)
		}
	}
 
	// Should be sorted
	for i := 1; i < len(rules); i++ {
		if rules[i] < rules[i-1] {
			t.Errorf("capability rules not sorted: %q before %q", rules[i-1], rules[i])
		}
	}
}

// network rule test
func TestConvertEndpointsToAppArmorRules(t *testing.T) {
	t.Run("with endpoints emits network rule", func(t *testing.T) {
		profile := &ApplicationProfile{
			Spec: ApplicationProfileSpec{
				Containers: []ContainerProfile{
					{
						Name: "nginx",
						Endpoints: []Endpoint{
							{Direction: "inbound", Endpoint: ":30080/index.html"},
						},
					},
				},
			},
		}
		rules := convertEndpointsToAppArmorRules(profile)
		if len(rules) != 1 {
			t.Fatalf("expected 1 network rule, got %d", len(rules))
		}
		if !strings.Contains(rules[0], "network") {
			t.Errorf("expected network rule, got %q", rules[0])
		}
	})
 
	t.Run("no endpoints emits no rule", func(t *testing.T) {
		profile := &ApplicationProfile{
			Spec: ApplicationProfileSpec{
				Containers: []ContainerProfile{
					{Name: "app"},
				},
			},
		}
		rules := convertEndpointsToAppArmorRules(profile)
		if len(rules) != 0 {
			t.Errorf("expected no network rules, got %v", rules)
		}
	})
 
	t.Run("multiple endpoints still emits only one network rule", func(t *testing.T) {
		profile := &ApplicationProfile{
			Spec: ApplicationProfileSpec{
				Containers: []ContainerProfile{
					{
						Name: "nginx",
						Endpoints: []Endpoint{
							{Direction: "inbound", Endpoint: ":30080/index.html"},
							{Direction: "inbound", Endpoint: ":30080/about.html"},
							{Direction: "inbound", Endpoint: ":30080/contact.html"},
						},
					},
				},
			},
		}
		rules := convertEndpointsToAppArmorRules(profile)
		if len(rules) != 1 {
			t.Errorf("expected exactly 1 network rule for multiple endpoints, got %d", len(rules))
		}
	})
}

func TestConvertNginxProfile(t *testing.T) {
	
	profile := &ApplicationProfile{
		Metadata: Metadata{Name: "replicaset-nginx-test-7d89557545"},
		Spec: ApplicationProfileSpec{
			Containers: []ContainerProfile{
				{
					Name: "nginx",
					Execs: []Exec{
						{Path: "/usr/sbin/nginx"},
						{Path: "/usr/bin/find"},
						{Path: "/docker-entrypoint.sh"},
					},
					Opens: []Open{
						{Path: "/etc/nginx/nginx.conf", Flags: []string{"O_RDONLY"}},
						{Path: "/var/log/nginx/access.log", Flags: []string{"O_WRONLY", "O_CREAT", "O_APPEND"}},
						{Path: "/proc/⋯/maps", Flags: []string{"O_RDONLY"}},
					},
					Capabilities: []string{"CAP_NET_ADMIN", "CAP_CHOWN"},
					Endpoints: []Endpoint{
						{Direction: "inbound", Endpoint: ":30080/index.html"},
					},
				},
			},
		},
	}
 
	converter := NewAppArmorConverter(profile, nil)
	output := converter.Convert()
 
	// Profile header
	if !strings.Contains(output, "profile bob_generated_profile") {
		t.Error("output missing expected profile name")
	}
	if !strings.Contains(output, "flags=(enforce)") {
		t.Error("output missing enforce flag")
	}
	if !strings.Contains(output, "#include <tunables/global>") {
		t.Errorf("output missing tunables include")
	}
	if !strings.Contains(output, "#include <abstractions/base>") {
		t.Error("output missing abstractions/base include")
	}
 
	// Exec rules
	if !strings.Contains(output, "/usr/sbin/nginx ix,") {
		t.Error("output missing exec rule for /usr/sbin/nginx")
	}
 
	// Read rule
	if !strings.Contains(output, "/etc/nginx/nginx.conf r,") {
		t.Error("output missing read rule for /etc/nginx/nginx.conf")
	}
 
	// Write rule + parent dir
	if !strings.Contains(output, "/var/log/nginx/access.log") {
		t.Error("output missing write rule for access.log")
	}
	if !strings.Contains(output, "/var/log/nginx/ w,") {
		t.Error("output missing parent dir write rule for /var/log/nginx/")
	}
 
	// Wildcard substitution
	if !strings.Contains(output, "/proc/*/maps") {
		t.Error("output missing wildcard path /proc/*/maps (⋯ not replaced)")
	}
 
	// Capability rules
	if !strings.Contains(output, "capability net_admin,") {
		t.Error("output missing capability net_admin")
	}
	if !strings.Contains(output, "capability chown,") {
		t.Error("output missing capability chown")
	}
 
	// Network rule
	if !strings.Contains(output, "network ,") {
		t.Error("output missing network rule")
	}
 
	// Closing brace
	if !strings.HasSuffix(strings.TrimSpace(output), "}") {
		t.Error("output does not end with closing brace")
	}
}

// test fallback naming
func TestConvertFallbackProfileName(t *testing.T) {
	profile := &ApplicationProfile{
		Metadata: Metadata{Name: ""},
		Spec: ApplicationProfileSpec{
			Containers: []ContainerProfile{
				{Name: "app"},
			},
		},
	}
 
	converter := NewAppArmorConverter(profile, nil)
	output := converter.Convert()
 
	if !strings.Contains(output, "profile bob_generated_profile") {
		t.Errorf("expected fallback profile name bob_generated_profile, got:\n%s", output)
	}
}

func TestConvertEmptyProfile(t *testing.T) {
	profile := &ApplicationProfile{
		Metadata: Metadata{Name: "empty-profile"},
		Spec:     ApplicationProfileSpec{},
	}
 
	converter := NewAppArmorConverter(profile, nil)
 
	// Should not panic and should produce a valid (minimal) profile
	output := converter.Convert()
 
	if !strings.Contains(output, "profile bob_generated_profile") {
		t.Error("empty profile missing profile header")
	}
	if !strings.Contains(output, "{") || !strings.Contains(output, "}") {
		t.Error("empty profile missing braces")
	}
}

func TestConvertInitContainersIncluded(t *testing.T) {
	profile := &ApplicationProfile{
		Metadata: Metadata{Name: "test"},
		Spec: ApplicationProfileSpec{
			Containers: []ContainerProfile{
				{
					Name:  "main",
					Execs: []Exec{{Path: "/app/server"}},
				},
			},
			InitContainers: []ContainerProfile{
				{
					Name:  "init",
					Execs: []Exec{{Path: "/bin/migrate"}},
				},
			},
		},
	}
 
	converter := NewAppArmorConverter(profile, nil)
	output := converter.Convert()
 
	if !strings.Contains(output, "/app/server ix,") {
		t.Error("main container exec /app/server missing from output")
	}
	if !strings.Contains(output, "/bin/migrate ix,") {
		t.Error("init container exec /bin/migrate missing from output")
	}
}

func TestConvertPathRulesMergedAcrossContainers(t *testing.T) {
	// Same path opened in two containers — permissions should be unioned
	profile := &ApplicationProfile{
		Metadata: Metadata{Name: "test"},
		Spec: ApplicationProfileSpec{
			Containers: []ContainerProfile{
				{
					Name:  "a",
					Opens: []Open{{Path: "/shared/config", Flags: []string{"O_RDONLY"}}},
				},
				{
					Name:  "b",
					Opens: []Open{{Path: "/shared/config", Flags: []string{"O_RDWR"}}},
				},
			},
		},
	}
 
	converter := NewAppArmorConverter(profile, nil)
	output := converter.Convert()
 
	// Should appear exactly once (merged), with rw permissions
	count := strings.Count(output, "/shared/config rw,")
	if count != 1 {
		t.Errorf("expected /shared/config rw, to appear once, got %d occurrences in:\n%s", count, output)
	}
}


