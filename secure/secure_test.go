package secure

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSameOrigin(t *testing.T) {
	const origin = "https://app.example.org"
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
	h := SameOrigin(origin, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(403) })(ok)

	cases := []struct {
		name    string
		method  string
		headers map[string]string
		want    int
	}{
		{"get is never checked", "GET", nil, 204},
		{"same origin", "POST", map[string]string{"Origin": "https://app.example.org", "Sec-Fetch-Site": "same-origin"}, 204},
		{"explicit default port", "POST", map[string]string{"Origin": "https://APP.example.org:443"}, 204},
		{"referer fallback", "POST", map[string]string{"Referer": "https://app.example.org/page?x=1"}, 204},
		{"no origin or referer", "POST", nil, 403},
		{"origin null", "POST", map[string]string{"Origin": "null"}, 403},
		{"sibling subdomain", "POST", map[string]string{"Origin": "https://other.example.org"}, 403},
		{"same-site fetch", "POST", map[string]string{"Origin": "https://app.example.org", "Sec-Fetch-Site": "same-site"}, 403},
		{"cross-site fetch", "DELETE", map[string]string{"Origin": "https://app.example.org", "Sec-Fetch-Site": "cross-site"}, 403},
		{"user-initiated none", "POST", map[string]string{"Origin": "https://app.example.org", "Sec-Fetch-Site": "none"}, 403},
		{"http downgrade", "POST", map[string]string{"Origin": "http://app.example.org"}, 403},
		{"lookalike suffix", "POST", map[string]string{"Origin": "https://app.example.org.evil.test"}, 403},
		{"userinfo", "POST", map[string]string{"Origin": "https://app.example.org@evil.test"}, 403},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest(c.method, "/x", nil)
			r.Host = "app.example.org" // never consulted, but realistic
			for k, v := range c.headers {
				r.Header.Set(k, v)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != c.want {
				t.Fatalf("status %d, want %d", w.Code, c.want)
			}
		})
	}
}

func TestHostHeaderIgnored(t *testing.T) {
	h := SameOrigin("https://app.example.org", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(403) })(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) }))
	r := httptest.NewRequest("POST", "/x", nil)
	r.Host = "evil.test"
	r.Header.Set("Origin", "https://evil.test")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("a forged Host must not make a foreign origin acceptable")
	}
}

func TestHeadersAndNonce(t *testing.T) {
	var seen string
	h := Headers(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { seen = Nonce(r.Context()) }))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	csp := w.Header().Get("Content-Security-Policy")
	if seen == "" || !strings.Contains(csp, "'nonce-"+seen+"'") {
		t.Fatalf("nonce %q not in CSP %q", seen, csp)
	}
	for _, banned := range []string{"unsafe-eval", "unsafe-inline", "*"} {
		if strings.Contains(csp, banned) {
			t.Fatalf("CSP contains %q: %s", banned, csp)
		}
	}
	w2 := httptest.NewRecorder()
	h.ServeHTTP(w2, httptest.NewRequest("GET", "/", nil))
	if w2.Header().Get("Content-Security-Policy") == csp {
		t.Fatal("the nonce must be fresh on every response")
	}
}
