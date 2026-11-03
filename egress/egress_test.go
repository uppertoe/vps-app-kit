package egress

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"testing"
)

func TestRefusals(t *testing.T) {
	c := New([]string{"api.example.org", "localhost"})
	ctx := context.Background()
	for _, u := range []string{
		"https://undeclared.example.org/",
		"http://api.example.org/",
		"https://api.example.org:8443/",
		"https://localhost/", // declared, but resolves to loopback
	} {
		_, err := Get(ctx, c, u)
		if !errors.Is(err, ErrRefused) {
			t.Errorf("%s: err = %v, want a refusal", u, err)
		}
	}
}

func TestRedirectToUndeclaredHostRefused(t *testing.T) {
	allowPrivate = true
	defer func() { allowPrivate = false }()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/go" {
			http.Redirect(w, r, "https://elsewhere.example.org/", http.StatusFound)
			return
		}
		w.WriteHeader(204)
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	c := New([]string{u.Hostname()})
	c.Transport.(guard).next.(*http.Transport).TLSClientConfig = srv.Client().Transport.(*http.Transport).TLSClientConfig
	resp, err := Get(context.Background(), c, srv.URL+"/ok")
	if err != nil || resp.StatusCode != 204 {
		t.Fatalf("declared host: %v %v", resp, err)
	}
	if _, err := Get(context.Background(), c, srv.URL+"/go"); !errors.Is(err, ErrRefused) {
		t.Fatalf("redirect: err = %v, want a refusal", err)
	}
}

func TestPublic(t *testing.T) {
	for addr, want := range map[string]bool{
		"1.1.1.1": true, "10.0.0.1": false, "172.17.0.2": false, "192.168.1.1": false,
		"127.0.0.1": false, "169.254.169.254": false, "100.64.0.1": false, "0.0.0.0": false,
		"::1": false, "fd00::1": false, "fe80::1": false, "::ffff:10.0.0.1": false,
		"64:ff9b::a00:1": false, "2606:4700::1111": true,
	} {
		if got := Public(netip.MustParseAddr(addr)); got != want {
			t.Errorf("Public(%s) = %v, want %v", addr, got, want)
		}
	}
}
