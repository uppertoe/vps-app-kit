// Package egress is the only HTTP client an app should use for outside
// services. It reaches only the hosts the app's manifest declares.
//
// The server's container firewall is the boundary actually enforced: it
// allows outbound traffic only to a short list of ports, not to named hosts.
// This client is a guard on the calls made through it, and the manifest is
// the reviewed record of which services the app talks to. kitlint fails on
// the usual ways app code makes another client or connection (http.Get and
// its siblings, the default client and transport, http.Client values and
// literals, new(http.Client), http.Transport, net and tls dials, httputil
// proxies, net/smtp), and every third-party library must be declared in
// app.yaml, so a library that brings its own client is seen in review. It
// is a check on ordinary code, not a sandbox: code written to evade it can.
package egress

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"syscall"
	"time"
)

// ErrRefused wraps every refusal, so callers can tell a policy refusal from a
// network failure.
var ErrRefused = errors.New("egress: refused")

// allowPrivate is set only by this package's tests, which serve on loopback.
var allowPrivate = false

// New returns a client that connects only to the given hosts, over HTTPS on
// port 443, and never to a private, loopback, link-local or metadata address
// whatever a host resolves to. Redirects are checked against the same rules.
// Proxy settings in the environment are ignored.
func New(hosts []string) *http.Client {
	allowed := map[string]bool{}
	for _, h := range hosts {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" || strings.ContainsAny(h, "/:*") {
			panic(fmt.Sprintf("egress: %q is not a bare host name", h))
		}
		allowed[h] = true
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second, Control: controlAddress}
	tr := &http.Transport{
		Proxy:                 nil,
		DialContext:           dialer.DialContext,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          10,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
	}
	check := func(r *http.Request) error {
		if r.URL.Scheme != "https" {
			return fmt.Errorf("%w: %s is not https", ErrRefused, r.URL.Redacted())
		}
		if p := r.URL.Port(); p != "" && p != "443" && !allowPrivate {
			return fmt.Errorf("%w: port %s", ErrRefused, p)
		}
		if !allowed[strings.ToLower(r.URL.Hostname())] {
			return fmt.Errorf("%w: %s is not declared in app.yaml", ErrRefused, r.URL.Hostname())
		}
		return nil
	}
	return &http.Client{
		Timeout:   60 * time.Second,
		Transport: guard{check: check, next: tr},
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("%w: too many redirects", ErrRefused)
			}
			return check(r)
		},
	}
}

type guard struct {
	check func(*http.Request) error
	next  http.RoundTripper
}

func (g guard) RoundTrip(r *http.Request) (*http.Response, error) {
	if err := g.check(r); err != nil {
		return nil, err
	}
	return g.next.RoundTrip(r)
}

// controlAddress runs after DNS resolution, on the exact address about to be
// dialled, so a host that resolves to an internal address is refused even
// when its name is declared.
func controlAddress(network, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrRefused, address)
	}
	if !allowPrivate {
		if ap.Port() != 443 {
			return fmt.Errorf("%w: port %d", ErrRefused, ap.Port())
		}
		if !Public(ap.Addr()) {
			return fmt.Errorf("%w: %s is not a public address", ErrRefused, ap.Addr())
		}
	}
	return nil
}

var blocked = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), // carrier-grade NAT
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("64:ff9b::/96"), // NAT64 can reach IPv4 internals
}

// Public reports whether a is a globally routable unicast address.
func Public(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsValid() || a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() ||
		a.IsLinkLocalMulticast() || a.IsMulticast() || a.IsUnspecified() || a.IsInterfaceLocalMulticast() {
		return false
	}
	for _, p := range blocked {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

// Get is a convenience for a GET with a context.
func Get(ctx context.Context, c *http.Client, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}
