package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/uppertoe/vps-app-kit/manifest"
)

const goodCompose = `services:
  demo:
    image: ghcr.io/acme/demo:sha-x
    user: "65532:65532"
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    read_only: true
    mem_limit: 128m
    pids_limit: 128
    healthcheck:
      test: ["CMD", "/app", "-healthcheck"]
`

func write(t *testing.T, root, rel, body string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func demo() *manifest.Manifest { return &manifest.Manifest{Name: "demo"} }

func rules(fs []finding) string {
	var r []string
	for _, f := range fs {
		r = append(r, f.rule+": "+f.msg)
	}
	return strings.Join(r, "\n")
}

func TestCompose(t *testing.T) {
	root := t.TempDir()
	write(t, root, "deploy/apps/demo/docker-compose.yml", goodCompose)
	if fs := checkCompose(root, demo()); len(fs) != 0 {
		t.Fatalf("good compose flagged:\n%s", rules(fs))
	}
	for name, mutate := range map[string]func(string) string{
		"root user":     func(s string) string { return strings.Replace(s, `"65532:65532"`, `"0:0"`, 1) },
		"no cap_drop":   func(s string) string { return strings.Replace(s, "cap_drop: [ALL]\n", "", 1) },
		"writable root": func(s string) string { return strings.Replace(s, "read_only: true", "read_only: false", 1) },
		"no mem limit":  func(s string) string { return strings.Replace(s, "mem_limit: 128m\n", "", 1) },
		"port":          func(s string) string { return s + "    ports: [\"8080:8080\"]\n" },
		"host network":  func(s string) string { return s + "    network_mode: host\n" },
		"extra network": func(s string) string { return s + "    networks: [other]\n" },
		"dev auth":      func(s string) string { return s + "    environment:\n      DEV_AUTH: \"1\"\n" },
		"renamed":       func(s string) string { return strings.Replace(s, "  demo:", "  web:", 1) },
		"docker socket": func(s string) string { return s + "    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n" },
		"host path":     func(s string) string { return s + "    volumes:\n      - /etc:/host-etc:ro\n" },
		"bind mount": func(s string) string {
			return s + "    volumes:\n      - type: bind\n        source: ./x\n        target: /x\n"
		},
		"cap_add":     func(s string) string { return s + "    cap_add: [SYS_ADMIN]\n" },
		"userns host": func(s string) string { return s + "    userns_mode: host\n" },
		"seccomp off": func(s string) string {
			return strings.Replace(s, `["no-new-privileges:true"]`, `["no-new-privileges:true", "seccomp:unconfined"]`, 1)
		},
		"nnp false": func(s string) string {
			return strings.Replace(s, `["no-new-privileges:true"]`, `["no-new-privileges:true", "no-new-privileges:false"]`, 1)
		},
		"external net": func(s string) string { return s + "networks:\n  other:\n    external: true\n" },
	} {
		write(t, root, "deploy/apps/demo/docker-compose.yml", mutate(goodCompose))
		if fs := checkCompose(root, demo()); len(fs) == 0 {
			t.Errorf("%s: not flagged", name)
		}
	}
}

func TestEnvExample(t *testing.T) {
	root := t.TempDir()
	write(t, root, "deploy/apps/demo/.env.example", "PUBLIC_URL=https://x\nSMTP_PASS=CHANGE_ME\nAPI_KEY=\n#SECRET_TOKEN=CHANGE_ME\n")
	if fs := checkEnvExample(root, demo()); len(fs) != 0 {
		t.Fatalf("good example flagged:\n%s", rules(fs))
	}
	write(t, root, "deploy/apps/demo/.env.example", "SMTP_PASS=hunter2-real\nDEV_AUTH=1\n")
	if fs := checkEnvExample(root, demo()); len(fs) != 2 {
		t.Fatalf("want 2 findings:\n%s", rules(fs))
	}
}

func TestDocs(t *testing.T) {
	root := t.TempDir()
	write(t, root, "design-docs/_index.md", "---\ntitle: Demo\nsummary: s\nstatus: live\ncontact: c\ndecided-by: d\n---\n\nBody with [a page](page.md).\n")
	write(t, root, "design-docs/page.md", "---\ntitle: Page\n---\n\nText.\n")
	if fs := checkDocs(root, demo()); len(fs) != 0 {
		t.Fatalf("good docs flagged:\n%s", rules(fs))
	}
	write(t, root, "design-docs/page.md", "---\ntitle: Page\n---\n\nSet ANTHROPIC_API_KEY and see [x](missing.md). 123e4567-e89b-12d3-a456-426614174000\n")
	write(t, root, "design-docs/_index.md", "---\ntitle: Demo\nstatus: draft\n---\n")
	got := rules(checkDocs(root, demo()))
	for _, want := range []string{"secret setting", "GUID", "missing.md", "status must be", "needs summary", "body text"} {
		if !strings.Contains(got, want) {
			t.Errorf("no finding mentioning %q:\n%s", want, got)
		}
	}
}

func TestDockerfile(t *testing.T) {
	root := t.TempDir()
	good := "# Never add -tags dev\nFROM golang:1.27@sha256:" + strings.Repeat("a", 64) + " AS build\nRUN go build ./cmd/server\nFROM gcr.io/distroless/static@sha256:" + strings.Repeat("b", 64) + "\nCOPY --from=build /out /app\n"
	write(t, root, "Dockerfile", good)
	if fs := checkDockerfile(root, demo()); len(fs) != 0 {
		t.Fatalf("good Dockerfile flagged:\n%s", rules(fs))
	}
	write(t, root, "Dockerfile", "FROM golang:1.27 AS build\nRUN go build -tags dev ./cmd/server\n")
	if fs := checkDockerfile(root, demo()); len(fs) != 2 {
		t.Fatalf("want an unpinned base and the dev tag:\n%s", rules(fs))
	}
}

func TestWorkflows(t *testing.T) {
	root := t.TempDir()
	sha := strings.Repeat("c", 40)
	write(t, root, ".github/workflows/ci.yml", "on: [push]\npermissions: {}\njobs:\n  ci:\n    uses: acme/kit/.github/workflows/app-ci.yml@"+sha+"\n")
	if fs := checkWorkflows(root, demo()); len(fs) != 0 {
		t.Fatalf("good workflow flagged:\n%s", rules(fs))
	}
	write(t, root, ".github/workflows/ci.yml", "on:\n  pull_request_target:\npermissions: write-all\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n")
	got := rules(checkWorkflows(root, demo()))
	for _, want := range []string{"pull_request_target", "write-all", "full commit SHA"} {
		if !strings.Contains(got, want) {
			t.Errorf("no finding mentioning %q:\n%s", want, got)
		}
	}
}

func TestVendor(t *testing.T) {
	root := t.TempDir()
	body := "console.log(1)"
	write(t, root, "internal/web/static/js/vendor/x.min.js", body)
	entry := `{"files":[{"path":"vendor/x.min.js","package":"x","version":"1.2.3","file":"/dist/x.min.js","url":"https://cdn.jsdelivr.net/npm/x@1.2.3/dist/x.min.js","sha256":"` + sum([]byte(body)) + `"}]}`
	write(t, root, "internal/web/static/js/VENDOR.json", entry)
	if fs := checkVendor(root, false); len(fs) != 0 {
		t.Fatalf("good vendor flagged:\n%s", rules(fs))
	}
	write(t, root, "internal/web/static/js/vendor/x.min.js", body+";evil()")
	write(t, root, "internal/web/static/js/vendor/y.min.js", "unlisted")
	if fs := checkVendor(root, false); len(fs) != 2 {
		t.Fatalf("want a hash mismatch and an unlisted file:\n%s", rules(fs))
	}
	write(t, root, "internal/web/static/js/VENDOR.json", strings.Replace(entry, "x@1.2.3", "x@latest", 1))
	if fs := checkVendor(root, false); !strings.Contains(rules(fs), "exact version") {
		t.Fatalf("a floating version was accepted:\n%s", rules(fs))
	}
}

func TestGoMod(t *testing.T) {
	root := t.TempDir()
	m := &manifest.Manifest{Name: "demo", Libraries: []manifest.Library{{Module: "gopkg.in/yaml.v3", Purpose: "reads the brand file"}}}
	good := "module x\n\ngo 1.26\n\nrequire (\n\tgithub.com/uppertoe/vps-app-kit v0.7.0\n\tgopkg.in/yaml.v3 v3.0.1\n)\n\nrequire golang.org/x/sys v0.1.0 // indirect\n"
	write(t, root, "go.mod", good)
	if fs := checkGoMod(root, m, "v0.7.0"); len(fs) != 0 {
		t.Fatalf("good go.mod flagged:\n%s", rules(fs))
	}
	write(t, root, "go.mod", good+"\nrequire github.com/aws/aws-sdk-go-v2 v1.30.0\n")
	if got := rules(checkGoMod(root, m, "")); !strings.Contains(got, "aws-sdk-go-v2 is a direct dependency") {
		t.Fatalf("an undeclared library passed:\n%s", got)
	}
	write(t, root, "go.mod", good+"\nreplace github.com/uppertoe/vps-app-kit => ../fork\n")
	if got := rules(checkGoMod(root, m, "")); !strings.Contains(got, "must not be replaced") {
		t.Fatalf("a replaced kit passed:\n%s", got)
	}
	write(t, root, "go.mod", strings.Replace(good, "v0.7.0", "v0.4.0", 1))
	if got := rules(checkGoMod(root, m, "v0.7.0")); !strings.Contains(got, "older than v0.7.0") {
		t.Fatalf("an old kit passed:\n%s", got)
	}
	for _, c := range []struct {
		a, b string
		less bool
	}{{"v0.4.0", "v0.7.0", true}, {"v0.7.0", "v0.7.0", false}, {"v0.10.0", "v0.7.0", false}, {"v0.7.1-0.2026", "v0.7.1", true}} {
		if semverLess(c.a, c.b) != c.less {
			t.Errorf("semverLess(%s, %s) != %v", c.a, c.b, c.less)
		}
	}
}
