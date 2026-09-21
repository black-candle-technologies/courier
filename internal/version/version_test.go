package version

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Unstamped builds (plain `go test`) must fall back to the dev default.
func TestDefaultsAreDev(t *testing.T) {
	for name, got := range map[string]string{
		"Client":    Client,
		"Relay":     Relay,
		"Dashboard": Dashboard,
		"Bridge":    Bridge,
	} {
		if got != "dev" {
			t.Errorf("version.%s = %q, want dev default in unstamped build", name, got)
		}
	}
}

// moduleRoot locates the courier module root from this test file's path.
func moduleRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	pkgDir := filepath.Dir(file) // .../internal/version
	root := filepath.Dir(filepath.Dir(pkgDir))
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("module root not found above %s: %v", pkgDir, err)
	}
	return root
}

// TestLdflagsStamping builds the stampfixture with -X flags and checks the
// stamped values surface at runtime. This pins the exact symbol paths that
// docs/versions.md tells release builds to use: if a path is renamed, this
// test fails instead of a release silently shipping "dev".
func TestLdflagsStamping(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not on PATH")
	}
	root := moduleRoot(t)
	bin := filepath.Join(t.TempDir(), "stampcheck")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	const mod = "github.com/black-candle-technologies/courier/internal/version"
	stamps := map[string]string{
		"Client":    "v9.9.9-client",
		"Relay":     "v9.9.9-relay",
		"Dashboard": "v9.9.9-dashboard",
		"Bridge":    "v9.9.9-bridge",
	}
	var ldflags strings.Builder
	for sym, val := range stamps {
		if ldflags.Len() > 0 {
			ldflags.WriteByte(' ')
		}
		ldflags.WriteString("-X " + mod + "." + sym + "=" + val)
	}
	build := exec.Command("go", "build", "-o", bin, "-ldflags", ldflags.String(), "./internal/version/stampfixture")
	build.Dir = root
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build stampfixture: %v\n%s", err, out)
	}
	run := exec.Command(bin)
	run.Dir = root
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("stampcheck: %v\n%s", err, out)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) != 4 {
		t.Fatalf("stampcheck printed %d lines, want 4:\n%s", len(lines), out)
	}
	for i, sym := range []string{"Client", "Relay", "Dashboard", "Bridge"} {
		if lines[i] != stamps[sym] {
			t.Errorf("version.%s stamped = %q, want %q", sym, lines[i], stamps[sym])
		}
	}
}
