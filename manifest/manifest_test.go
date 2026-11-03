package manifest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const good = `
name: fellows
title: Fellowship enquiries
subdomain: enquiries
data_class: health
health_attestation: compliance/health-attestation.md
outbound:
  - host: api.anthropic.com
    purpose: Drafts a summary of each enquiry for staff
    data: The enquiry text, without the applicant's contact details
email:
  smtp_host: email-smtp.ap-southeast-2.amazonaws.com
  purpose: Replies to applicants
  data: The message staff write and the applicant's address
webhooks:
  - path: /hooks/github
    from: GitHub
    purpose: Rebuilds the public pages when their copy changes
`

func TestParse(t *testing.T) {
	m, err := Parse([]byte(good))
	if err != nil {
		t.Fatal(err)
	}
	if m.Port != 8080 || m.SiteHost() != "enquiries.{$DOMAIN}" || len(m.Hosts()) != 1 {
		t.Fatalf("%+v", m)
	}
	page := m.ConnectionsPage()
	for _, want := range []string{"title: Connections", "`api.anthropic.com`", "`/hooks/github`", "email-smtp"} {
		if !strings.Contains(page, want) {
			t.Errorf("page lacks %q", want)
		}
	}
}

func TestHealthAttestation(t *testing.T) {
	m, _ := Parse([]byte(good))
	root := t.TempDir()
	if !m.HealthUnattested(root) {
		t.Fatal("no attestation file yet")
	}
	os.MkdirAll(filepath.Join(root, "compliance"), 0o755)
	os.WriteFile(filepath.Join(root, "compliance", "health-attestation.md"), []byte("x"), 0o644)
	if m.HealthUnattested(root) {
		t.Fatal("attestation exists")
	}
}

func TestRefusals(t *testing.T) {
	for name, y := range map[string]string{
		"unknown field":   "name: a\ntitle: A\nsubdomain: a\ndata_class: none\nhosts: []\n",
		"bad class":       "name: a\ntitle: A\nsubdomain: a\ndata_class: secret\n",
		"url not host":    "name: a\ntitle: A\nsubdomain: a\ndata_class: none\noutbound:\n  - host: https://x.org/\n    purpose: p\n    data: d\n",
		"wildcard host":   "name: a\ntitle: A\nsubdomain: a\ndata_class: none\noutbound:\n  - host: '*.x.org'\n    purpose: p\n    data: d\n",
		"secret in text":  "name: a\ntitle: A\nsubdomain: a\ndata_class: none\noutbound:\n  - host: x.org\n    purpose: uses ANTHROPIC_API_KEY\n    data: d\n",
		"missing purpose": "name: a\ntitle: A\nsubdomain: a\ndata_class: none\noutbound:\n  - host: x.org\n    data: d\n",
		"bad name":        "name: My App\ntitle: A\nsubdomain: a\ndata_class: none\n",
	} {
		if _, err := Parse([]byte(y)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
