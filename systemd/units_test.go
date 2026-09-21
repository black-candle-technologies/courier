// Regression test for issue #114: the systemd service units must keep
// their sandboxing directives. A unit that quietly loses its hardening
// (for example during an ExecStart edit) fails loudly here.
package systemd_test

import (
	"bufio"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// loadServiceSection parses the [Service] section of a unit file into a
// key→value map (last value wins on repeats; key presence is recorded
// even for empty values such as "CapabilityBoundingSet=").
func loadServiceSection(t *testing.T, name string) map[string]string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	f, err := os.Open(filepath.Join(filepath.Dir(thisFile), name))
	if err != nil {
		t.Fatalf("open %s: %v", name, err)
	}
	defer f.Close()

	out := map[string]string{}
	inService := false
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			inService = line == "[Service]"
			continue
		}
		if !inService {
			continue
		}
		key, val, found := strings.Cut(line, "=")
		if !found {
			t.Fatalf("%s: malformed line %q", name, line)
		}
		out[strings.TrimSpace(key)] = strings.TrimSpace(val)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan %s: %v", name, err)
	}
	return out
}

func containsAll(haystack string, needles ...string) bool {
	for _, n := range needles {
		if !strings.Contains(haystack, n) {
			return false
		}
	}
	return true
}

func TestUnitsStaySandboxed(t *testing.T) {
	units := []string{
		"courier-relay.service",
		"courier-dashboard.service",
		"courier-bridge-gateway.service",
		"courier-bridge-mcp.service",
	}
	for _, name := range units {
		svc := loadServiceSection(t, name)

		if u := svc["User"]; u == "" || u == "root" {
			t.Errorf("%s: must run as an unprivileged user, got %q", name, u)
		}
		boolDirectives := map[string]string{
			"NoNewPrivileges":       "true",
			"PrivateTmp":            "true",
			"ProtectHome":           "true",
			"PrivateDevices":        "true",
			"ProtectKernelTunables": "true",
			"ProtectKernelModules":  "true",
			"ProtectControlGroups":  "true",
			"ProtectClock":          "true",
			"ProtectHostname":       "true",
			"RestrictRealtime":      "true",
			"RestrictSUIDSGID":      "true",
			"LockPersonality":       "true",
			"RestrictNamespaces":    "true",
		}
		for key, want := range boolDirectives {
			if got := svc[key]; got != want {
				t.Errorf("%s: %s must be %q, got %q", name, key, want, got)
			}
		}
		if got := svc["ProtectSystem"]; got != "strict" {
			t.Errorf("%s: ProtectSystem must be strict, got %q", name, got)
		}
		if af := svc["RestrictAddressFamilies"]; !containsAll(af, "AF_INET", "AF_INET6") {
			t.Errorf("%s: RestrictAddressFamilies must include AF_INET and AF_INET6, got %q", name, af)
		}
		if _, ok := svc["CapabilityBoundingSet"]; !ok {
			t.Errorf("%s: CapabilityBoundingSet must be set explicitly", name)
		}
		if !strings.Contains(svc["SystemCallFilter"], "@system-service") {
			t.Errorf("%s: SystemCallFilter must include @system-service, got %q", name, svc["SystemCallFilter"])
		}
		if svc["MemoryMax"] == "" {
			t.Errorf("%s: MemoryMax must be set", name)
		}
		if svc["TasksMax"] == "" {
			t.Errorf("%s: TasksMax must be set", name)
		}
		if svc["StateDirectory"] == "" && svc["ReadWritePaths"] == "" {
			t.Errorf("%s: must declare its writable path via StateDirectory or ReadWritePaths", name)
		}
		if exec := svc["ExecStart"]; !strings.HasPrefix(exec, "/") {
			t.Errorf("%s: ExecStart must use an absolute binary path, got %q", name, exec)
		}
		if env := svc["EnvironmentFile"]; env != "" && !strings.HasPrefix(env, "/") {
			t.Errorf("%s: EnvironmentFile must use an absolute path, got %q", name, env)
		}
	}
}

func TestUnitsWritablePaths(t *testing.T) {
	cases := []struct {
		name string
		key  string
		want string
	}{
		{"courier-relay.service", "StateDirectory", "courier"},
		{"courier-dashboard.service", "StateDirectory", "courier"},
		{"courier-bridge-gateway.service", "ReadWritePaths", "/opt/courier-bridge"},
		{"courier-bridge-mcp.service", "ReadWritePaths", "/opt/courier-bridge-mcp"},
	}
	for _, c := range cases {
		svc := loadServiceSection(t, c.name)
		if got := svc[c.key]; got != c.want {
			t.Errorf("%s: %s must be %q, got %q", c.name, c.key, c.want, got)
		}
	}
}
