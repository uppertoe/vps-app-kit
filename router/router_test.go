package router

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/uppertoe/vps-app-kit/access"
	"github.com/uppertoe/vps-app-kit/gateway"
	"github.com/uppertoe/vps-app-kit/webhook"
)

var hookKey = []byte("0123456789abcdef0123456789abcdef")

// memReplay is an in-memory webhook.Replay for these tests.
type memReplay struct{ done map[string]bool }

func (m *memReplay) Claim(_ context.Context, id string, _ time.Duration) (webhook.Claim, error) {
	if m.done[id] {
		return webhook.Done, nil
	}
	return webhook.Claimed, nil
}
func (m *memReplay) Complete(_ context.Context, id string, _ time.Time) error {
	if m.done == nil {
		m.done = map[string]bool{}
	}
	m.done[id] = true
	return nil
}
func (m *memReplay) Release(context.Context, string) error { return nil }

var deliveries int

// signGitHub signs an empty delivery as GitHub would, with a fresh ID.
func signGitHub(r *http.Request) {
	deliveries++
	mac := hmac.New(sha256.New, hookKey)
	r.Header.Set("X-GitHub-Delivery", fmt.Sprint("d", deliveries))
	r.Header.Set("X-Hub-Signature-256", "sha256="+hex.EncodeToString(mac.Sum(nil)))
}

const origin = "https://app.example.org"

func newTestRouter() *Router {
	rt := New(Options{PublicOrigin: origin})
	echo := func(w http.ResponseWriter, r *http.Request) {
		id, ok := gateway.From(r.Context())
		if ok {
			w.Write([]byte("id:" + id.Email))
			return
		}
		// Proves a handler on an anonymous route sees no identity header.
		w.Write([]byte("anon:" + r.Header.Get(gateway.HeaderEmail) + r.Header.Get(gateway.HeaderGroups)))
	}
	rt.HandleFunc("GET /{$}", access.Public("landing page"), echo)
	rt.HandleFunc("POST /enquire", access.Public("enquiry form"), echo)
	rt.Handle("POST /hooks/github", access.Webhook("repository pushes"),
		webhook.Handler(webhook.NewGitHub(hookKey), &memReplay{}, webhook.Options{}, func(w http.ResponseWriter, r *http.Request, _ []byte) { echo(w, r) }))
	rt.HandleFunc("GET /home", access.SignedIn(), echo)
	rt.HandleFunc("GET /apply", access.SignedInOrGuest(), echo)
	rt.HandleFunc("GET /staff/", access.Domain("rch.org.au"), echo)
	rt.HandleFunc("GET /admin/", access.Group("fellowship_admin"), echo)
	rt.HandleFunc("POST /admin/{id}/note", access.Group("fellowship_admin"), echo)
	return rt
}

type ident struct{ email, groups string }

var (
	anon   = ident{}
	guest  = ident{"g@gmail.com", "guest"}
	user   = ident{"u@monash.edu", "user"}
	staff  = ident{"s@rch.org.au", "user"}
	member = ident{"m@monash.edu", "user,fellowship_admin"}
	admin  = ident{"a@elsewhere.org", "admin"}
)

func do(rt http.Handler, method, path string, id ident, extra map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, nil)
	if id.email != "" {
		r.Header.Set(gateway.HeaderEmail, id.email)
		r.Header.Set(gateway.HeaderUser, id.email)
		r.Header.Set(gateway.HeaderGroups, id.groups)
	}
	if method != "GET" {
		r.Header.Set("Origin", origin)
	}
	for k, v := range extra {
		r.Header.Set(k, v)
	}
	if strings.HasPrefix(path, "/hooks/") {
		signGitHub(r)
	}
	w := httptest.NewRecorder()
	rt.ServeHTTP(w, r)
	return w
}

func TestAccessMatrix(t *testing.T) {
	rt := newTestRouter()
	cases := []struct {
		method, path string
		who          ident
		want         int
	}{
		{"GET", "/home", anon, 401},
		{"GET", "/home", guest, 403},
		{"GET", "/home", user, 200},
		{"GET", "/apply", guest, 200},
		{"GET", "/apply", anon, 401},
		{"GET", "/staff/rota", staff, 200},
		{"GET", "/staff/rota", user, 403},
		{"GET", "/staff/rota", admin, 403},
		{"GET", "/admin/", member, 200},
		{"GET", "/admin/", staff, 403},
		{"GET", "/admin/", guest, 403},
		{"POST", "/admin/7/note", member, 200},
		{"GET", "/", anon, 200},
		{"GET", "/healthz", anon, 200},
		{"GET", "/nowhere", member, 404},
	}
	for _, c := range cases {
		w := do(rt, c.method, c.path, c.who, nil)
		if w.Code != c.want {
			t.Errorf("%s %s as %q: status %d, want %d", c.method, c.path, c.who.email, w.Code, c.want)
		}
	}
}

func TestAnonymousRoutesNeverSeeIdentity(t *testing.T) {
	rt := newTestRouter()
	for _, p := range []struct{ method, path string }{{"GET", "/"}, {"POST", "/enquire"}, {"POST", "/hooks/github"}} {
		w := do(rt, p.method, p.path, admin, nil)
		if body := w.Body.String(); body != "anon:" {
			t.Errorf("%s %s: handler saw %q", p.method, p.path, body)
		}
	}
}

func TestRepeatedHeaderRefused(t *testing.T) {
	rt := newTestRouter()
	r := httptest.NewRequest("GET", "/home", nil)
	r.Header.Add(gateway.HeaderEmail, "u@monash.edu")
	r.Header.Add(gateway.HeaderGroups, "user")
	r.Header.Add(gateway.HeaderGroups, "admin")
	w := httptest.NewRecorder()
	rt.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatalf("status %d, want 401", w.Code)
	}
}

func TestCrossSiteWrites(t *testing.T) {
	rt := newTestRouter()
	foreign := map[string]string{"Origin": "https://other.example.org"}
	if w := do(rt, "POST", "/admin/7/note", member, foreign); w.Code != 403 {
		t.Errorf("gated write from a sibling: %d", w.Code)
	}
	if w := do(rt, "POST", "/enquire", anon, foreign); w.Code != 403 {
		t.Errorf("public write from a sibling: %d", w.Code)
	}
	if w := do(rt, "POST", "/hooks/github", anon, foreign); w.Code != 200 {
		t.Errorf("a webhook is exempt from the origin check: %d", w.Code)
	}
}

func TestGatedResponsesAreNotCached(t *testing.T) {
	rt := newTestRouter()
	w := do(rt, "GET", "/home", user, nil)
	if w.Header().Get("Cache-Control") != "no-store" || !strings.Contains(w.Header().Get("Vary"), "HX-Request") {
		t.Fatalf("headers %v", w.Header())
	}
	if w.Header().Get("Content-Security-Policy") == "" {
		t.Fatal("no CSP")
	}
}

func TestRegistrationMistakesPanic(t *testing.T) {
	mustPanic := func(name string, f func()) {
		t.Helper()
		defer func() {
			if recover() == nil {
				t.Errorf("%s: expected a panic", name)
			}
		}()
		f()
	}
	h := func(http.ResponseWriter, *http.Request) {}
	mustPanic("zero level", func() { New(Options{PublicOrigin: origin}).HandleFunc("GET /x", access.Level{}, h) })
	mustPanic("two levels one path", func() {
		rt := New(Options{PublicOrigin: origin})
		rt.HandleFunc("GET /x", access.SignedIn(), h)
		rt.HandleFunc("POST /x", access.Public("form"), h)
	})
	mustPanic("host in pattern", func() { New(Options{PublicOrigin: origin}).HandleFunc("GET example.org/x", access.SignedIn(), h) })
	mustPanic("reserved dev path", func() { New(Options{PublicOrigin: origin}).HandleFunc("GET /dev/x", access.SignedIn(), h) })
	mustPanic("no origin", func() { New(Options{}) })
}

func TestDevRouteAbsent(t *testing.T) {
	if w := do(newTestRouter(), "GET", "/dev/identity", anon, nil); w.Code != 404 {
		t.Fatalf("/dev/identity answered %d in a normal build", w.Code)
	}
}

func TestCaddySnippet(t *testing.T) {
	out, err := newTestRouter().Caddy(Site{Name: "fellows", Host: "enquiries.{$DOMAIN}"})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"enquiries.{$DOMAIN} {",
		"path /admin /admin/*",
		`import protected_groups "fellowship_admin" fellows:8080`,
		`import protected_domains "rch.org.au" fellows:8080`,
		"import protected_open fellows:8080",
		"import protected fellows:8080",
		"import strip_public",
		"# scaffold-lint: open-path -- /: landing page",
		"# scaffold-lint: open-path -- /hooks/github: a signed webhook from repository pushes",
		"max_size 262144",
		"respond 404",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("snippet lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "strip_auth_cookie") {
		t.Error("public routes must use strip_public")
	}
	// Exact paths before prefixes, longer prefixes before shorter, and the
	// 404 catch-all last.
	idx := func(s string) int { return strings.Index(out, s) }
	if !(idx("path /home") < idx("path /admin /admin/*") && idx("path /admin /admin/*") < idx("respond 404")) {
		t.Errorf("blocks out of order:\n%s", out)
	}
	if err := checkComments(out); err != nil {
		t.Error(err)
	}
	if strings.Count(out, "{") != strings.Count(out, "}") {
		t.Error("unbalanced braces")
	}
}

func TestCaddyRefusesAmbiguousPrefixes(t *testing.T) {
	rt := New(Options{PublicOrigin: origin})
	h := func(http.ResponseWriter, *http.Request) {}
	rt.HandleFunc("GET /p/{id}", access.Public("profile pages"), h)
	rt.HandleFunc("GET /p/{id}/edit", access.SignedIn(), h)
	if _, err := rt.Caddy(Site{Name: "x", Host: "x.{$DOMAIN}"}); err == nil {
		t.Fatal("expected an error: Caddy cannot tell these two apart")
	}
}

func TestCaddyPaths(t *testing.T) {
	cases := map[string]string{
		"/{$}":             "/",
		"/faq":             "/faq",
		"/static/":         "/static /static/*",
		"/":                "/*",
		"/p/{id}":          "/p/*",
		"/p/{id}/edit":     "/p/*",
		"/files/{rest...}": "/files/*",
		"/a/b{x}":          "/a/*",
	}
	for in, want := range cases {
		got, _, _ := caddyPaths(in)
		if strings.Join(got, " ") != want {
			t.Errorf("caddyPaths(%q) = %v, want %s", in, got, want)
		}
	}
}

func TestCaddyMembersMarker(t *testing.T) {
	out, err := newTestRouter().Caddy(Site{Name: "fellows", Host: "x.{$DOMAIN}", MemberGroups: []string{"coordinators", "leads"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "# scaffold-members: coordinators leads -- ") {
		t.Fatalf("no marker:\n%s", out)
	}
	plain, _ := newTestRouter().Caddy(Site{Name: "fellows", Host: "x.{$DOMAIN}"})
	if strings.Contains(plain, "scaffold-members") {
		t.Fatal("a marker without member groups")
	}
}

// Requests are served concurrently; run with -race.
func TestConcurrentRequests(t *testing.T) {
	rt := newTestRouter()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			do(rt, "GET", "/home", user, nil)
		}()
	}
	wg.Wait()
	defer func() {
		if recover() == nil {
			t.Fatal("registering after serving must panic")
		}
	}()
	rt.HandleFunc("GET /late", access.SignedIn(), func(http.ResponseWriter, *http.Request) {})
}

func TestWebhookRoutesMustVerify(t *testing.T) {
	rt := New(Options{PublicOrigin: origin})
	defer func() {
		if recover() == nil {
			t.Fatal("a webhook route with an unverified handler must panic")
		}
	}()
	rt.HandleFunc("POST /hooks/x", access.Webhook("x"), func(http.ResponseWriter, *http.Request) {})
}

func TestUnbuiltWebhookAnswers404(t *testing.T) {
	rt := New(Options{PublicOrigin: origin})
	var notBuilt *webhook.Endpoint
	rt.Handle("POST /hooks/x", access.Webhook("x"), notBuilt)
	r := httptest.NewRequest("POST", "/hooks/x", nil)
	w := httptest.NewRecorder()
	rt.ServeHTTP(w, r)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status %d", w.Code)
	}
}

func TestPublicOriginMustBeExact(t *testing.T) {
	for _, o := range []string{"https://app.example.org/app", "https://app.example.org/?x=1", "https://app.example.org/#f", "app.example.org"} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%q accepted", o)
				}
			}()
			New(Options{PublicOrigin: o})
		}()
	}
	New(Options{PublicOrigin: "https://app.example.org/"})
}

func TestAllPublicSiteCarriesPublicMarker(t *testing.T) {
	rt := New(Options{PublicOrigin: origin})
	rt.HandleFunc("GET /{$}", access.Public("the landing page"), func(http.ResponseWriter, *http.Request) {})
	out, err := rt.Caddy(Site{Name: "x", Host: "x.{$DOMAIN}"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "# scaffold-lint: public -- container health check; the landing page\nx.{$DOMAIN} {") {
		t.Fatalf("no site-level public marker:\n%s", out)
	}
	if strings.Contains(out, "open-path") {
		t.Fatal("an all-public site needs no open-path markers")
	}
}
