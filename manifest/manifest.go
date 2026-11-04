// Package manifest reads an app's app.yaml: what the app is called, where it
// is served, what class of data it holds, and every connection it makes.
//
// The manifest is the reviewed record of the app's connections. The egress
// client reaches only the hosts it lists, CI generates the app's
// connections page in design-docs from it, and a change to it shows in a
// pull request like any other code.
package manifest

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// DataClass is the most sensitive kind of information the app holds.
type DataClass string

const (
	DataNone     DataClass = "none"
	DataPersonal DataClass = "personal"
	DataHealth   DataClass = "health"
)

// Manifest is app.yaml.
type Manifest struct {
	// Name is the folder and service name under apps/ in the server repo.
	Name string `yaml:"name"`
	// Title is the app's name as people see it.
	Title string `yaml:"title"`
	// Subdomain is the first label of the site address; the generated
	// snippet serves <subdomain>.{$DOMAIN}.
	Subdomain string `yaml:"subdomain"`
	// Port the container listens on. Default 8080.
	Port int `yaml:"port"`
	// DataClass is none, personal or health.
	DataClass DataClass `yaml:"data_class"`
	// HealthAttestation is the repo-relative path of the file recording
	// that the health-information safeguards are in place on the target
	// server. Until it exists, a health app warns and shows a banner.
	HealthAttestation string `yaml:"health_attestation"`
	// Outbound lists every outside service the app calls over HTTPS.
	Outbound []Outbound `yaml:"outbound"`
	// Email describes sending, when the app sends email.
	Email *Email `yaml:"email"`
	// Webhooks lists every service that sends the app signed deliveries.
	Webhooks []Webhook `yaml:"webhooks"`
	// Members lists the gateway groups whose members the app reads when
	// nobody is signed in, such as for a weekly email to a group. The
	// server's route renderer gives the app a private network to the
	// gateway's members endpoint only when this list is not empty.
	Members []string `yaml:"members"`
	// Libraries lists every third-party Go module the app requires
	// directly, other than vps-app-kit, with what it is for. kitlint all
	// fails on an undeclared one, so a library that brings its own network
	// client or runs programs is seen in review.
	Libraries []Library `yaml:"libraries"`
}

// Library is one direct third-party dependency.
type Library struct {
	Module  string `yaml:"module"`
	Purpose string `yaml:"purpose"`
}

// Outbound is one outside HTTPS service.
type Outbound struct {
	Host    string `yaml:"host"`
	Purpose string `yaml:"purpose"`
	// Data says what information the service receives.
	Data string `yaml:"data"`
}

// Email is the app's sending.
type Email struct {
	SMTPHost string `yaml:"smtp_host"`
	Purpose  string `yaml:"purpose"`
	Data     string `yaml:"data"`
}

// Webhook is one service that sends deliveries.
type Webhook struct {
	Path    string `yaml:"path"`
	From    string `yaml:"from"`
	Purpose string `yaml:"purpose"`
}

var (
	nameRe = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)
	hostRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)
	// The docs-site contract refuses secret-shaped setting names and GUIDs;
	// manifest text is published there, so it is refused here first.
	secretNameRe = regexp.MustCompile(`[A-Z0-9_]*_(TOKEN|SECRET|PASSWORD|PASS|KEY)\b`)
	guidRe       = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`)
)

// Load reads and validates app.yaml. Unknown fields are an error, so a
// misspelt key is not silently ignored.
func Load(path string) (*Manifest, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(b)
}

// Parse validates a manifest's bytes.
func Parse(b []byte) (*Manifest, error) {
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	var m Manifest
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("app.yaml: %w", err)
	}
	if m.Port == 0 {
		m.Port = 8080
	}
	return &m, m.validate()
}

func (m *Manifest) validate() error {
	var errs []error
	bad := func(format string, a ...any) { errs = append(errs, fmt.Errorf("app.yaml: "+format, a...)) }
	if !nameRe.MatchString(m.Name) {
		bad("name %q must be lower-case letters, digits and hyphens", m.Name)
	}
	if !nameRe.MatchString(m.Subdomain) {
		bad("subdomain %q must be one lower-case label", m.Subdomain)
	}
	if strings.TrimSpace(m.Title) == "" {
		bad("title is required")
	}
	switch m.DataClass {
	case DataNone, DataPersonal, DataHealth:
	default:
		bad("data_class must be none, personal or health, not %q", m.DataClass)
	}
	text := func(where, s string) {
		if strings.TrimSpace(s) == "" {
			bad("%s is required", where)
		}
		if secretNameRe.MatchString(s) || guidRe.MatchString(s) {
			bad("%s must not name a secret setting or contain an identifier: it is published in the design docs", where)
		}
	}
	seen := map[string]bool{}
	for i, o := range m.Outbound {
		h := strings.ToLower(o.Host)
		if !hostRe.MatchString(h) {
			bad("outbound[%d].host %q must be a bare host name", i, o.Host)
		}
		if seen[h] {
			bad("outbound host %s is listed twice", h)
		}
		seen[h] = true
		text(fmt.Sprintf("outbound[%d].purpose", i), o.Purpose)
		text(fmt.Sprintf("outbound[%d].data", i), o.Data)
	}
	if m.Email != nil {
		if !hostRe.MatchString(strings.ToLower(m.Email.SMTPHost)) {
			bad("email.smtp_host %q must be a bare host name", m.Email.SMTPHost)
		}
		text("email.purpose", m.Email.Purpose)
		text("email.data", m.Email.Data)
	}
	for i, w := range m.Webhooks {
		if !strings.HasPrefix(w.Path, "/") {
			bad("webhooks[%d].path must start with /", i)
		}
		text(fmt.Sprintf("webhooks[%d].from", i), w.From)
		text(fmt.Sprintf("webhooks[%d].purpose", i), w.Purpose)
	}
	modRe := regexp.MustCompile(`^[a-z0-9.-]+\.[a-z]{2,}(/[A-Za-z0-9._~-]+)+$`)
	for i, l := range m.Libraries {
		if !modRe.MatchString(l.Module) {
			bad("libraries[%d].module %q must be a Go module path", i, l.Module)
		}
		text(fmt.Sprintf("libraries[%d].purpose", i), l.Purpose)
	}
	groupRe := regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)
	seenGroup := map[string]bool{}
	for i, g := range m.Members {
		if !groupRe.MatchString(g) || g == "admin" || g == "user" || g == "guest" {
			bad("members[%d] %q must be a gateway group name, not a role", i, g)
		}
		if seenGroup[g] {
			bad("members lists %s twice", g)
		}
		seenGroup[g] = true
	}
	return errors.Join(errs...)
}

// Hosts returns the outbound hosts, for egress.New.
func (m *Manifest) Hosts() []string {
	var hs []string
	for _, o := range m.Outbound {
		hs = append(hs, strings.ToLower(o.Host))
	}
	return hs
}

// SiteHost is the site address for the generated Caddy snippet.
func (m *Manifest) SiteHost() string { return m.Subdomain + ".{$DOMAIN}" }

// HealthUnattested reports whether the app holds health information and the
// attestation file named in the manifest does not exist under repoRoot.
func (m *Manifest) HealthUnattested(repoRoot string) bool {
	if m.DataClass != DataHealth {
		return false
	}
	if m.HealthAttestation == "" {
		return true
	}
	_, err := os.Stat(filepath.Join(repoRoot, filepath.Clean(m.HealthAttestation)))
	return err != nil
}

// ConnectionsPage renders design-docs/connections.md. It names hosts and
// what each receives, never a setting's name.
func (m *Manifest) ConnectionsPage() string {
	var b strings.Builder
	w := func(s string) { b.WriteString(s + "\n") }
	cell := func(s string) string { return strings.ReplaceAll(strings.TrimSpace(s), "|", "/") }
	w("---")
	w("title: Connections")
	w("summary: Every service that sends information to the app, and every service the app sends information to.")
	w("---")
	w("")
	w("This page is generated from the app's manifest (`app.yaml`). Do not edit it by hand.")
	w("")
	w("## What reaches the app")
	w("")
	w("People reach the app only through the platform's sign-in gateway, except on the routes the app declares public.")
	if len(m.Webhooks) > 0 {
		w("")
		w("| Path | Sent by | Purpose |")
		w("|---|---|---|")
		for _, x := range m.Webhooks {
			w("| `" + cell(x.Path) + "` | " + cell(x.From) + " | " + cell(x.Purpose) + " |")
		}
		w("")
		w("Each delivery is admitted only with a valid signature from its sender.")
	}
	if len(m.Members) > 0 {
		w("")
		w("The app reads the members of these groups from the sign-in service, inside the server, when it needs them: " +
			"`" + strings.Join(m.Members, "`, `") + "`. It keeps no copy of the members.")
	}
	if len(m.Libraries) > 0 {
		w("")
		w("The app is built with these third-party libraries, besides the platform's own kit:")
		w("")
		w("| Library | What it is for |")
		w("|---|---|")
		for _, l := range m.Libraries {
			w("| `" + cell(l.Module) + "` | " + cell(l.Purpose) + " |")
		}
	}
	w("")
	w("## What leaves the server")
	w("")
	if len(m.Outbound) == 0 && m.Email == nil {
		w("The app sends information to no outside service.")
	} else {
		w("| Service | Purpose | Information it receives |")
		w("|---|---|---|")
		for _, o := range m.Outbound {
			w("| `" + cell(o.Host) + "` | " + cell(o.Purpose) + " | " + cell(o.Data) + " |")
		}
		if m.Email != nil {
			w("| Email through `" + cell(m.Email.SMTPHost) + "` | " + cell(m.Email.Purpose) + " | " + cell(m.Email.Data) + " |")
		}
		w("")
		w("The app's HTTP client refuses any host not listed here, and the server's firewall allows outbound connections only on a short list of ports.")
	}
	return b.String()
}
