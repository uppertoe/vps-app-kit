package main

import (
	"os"
	"regexp"
	"testing"
)

// The reusable app workflow names the kitlint and kitgate it runs (KIT_TOOLS)
// and the oldest kit an app may require (MIN_KIT). Every app's CI runs
// "go run ...@KIT_TOOLS", so a malformed value, or a minimum newer than the
// tools that enforce it, would fail every app at once. This test reads the
// workflow file itself, so the kit's own CI catches that before a release.
func TestAppWorkflowNamesWellFormedKitVersions(t *testing.T) {
	b, err := os.ReadFile("../../.github/workflows/app-ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	value := func(name string) string {
		m := regexp.MustCompile(`(?m)^\s*` + name + `:\s*(\S+)\s*$`).FindSubmatch(b)
		if m == nil {
			t.Fatalf("app-ci.yml does not set %s", name)
		}
		return string(m[1])
	}
	release := regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`)
	tools, min := value("KIT_TOOLS"), value("MIN_KIT")
	for name, v := range map[string]string{"KIT_TOOLS": tools, "MIN_KIT": min} {
		if !release.MatchString(v) {
			t.Errorf("%s is %q; it must be a release tag such as v0.7.0", name, v)
		}
	}
	if semverLess(tools, min) {
		t.Errorf("KIT_TOOLS %s is older than MIN_KIT %s: the tools that enforce the minimum must be at least as new as it", tools, min)
	}
}
