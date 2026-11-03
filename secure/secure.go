// Package secure sets the response headers every page needs and refuses
// cross-site writes.
package secure

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
)

type nonceKey struct{}

// Nonce returns the CSP script nonce for this response, for the one inline
// script a layout may carry. It is "" outside Headers.
func Nonce(ctx context.Context) string {
	n, _ := ctx.Value(nonceKey{}).(string)
	return n
}

func newNonce() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:])
}

// CSP is the policy for a response with the given nonce. There is no
// 'unsafe-eval' (Alpine's CSP build needs none) and no 'unsafe-inline' for
// styles: templates style through classes and custom properties, and script
// sets element.style through the CSSOM, which the policy allows.
func CSP(nonce string) string {
	return "default-src 'self'; script-src 'self' 'nonce-" + nonce + "'; style-src 'self'; " +
		"img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; " +
		"form-action 'self'; frame-ancestors 'none'; base-uri 'none'"
}

// Headers sets the security headers and a fresh nonce on every response.
func Headers(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonce := newNonce()
		h := w.Header()
		h.Set("Content-Security-Policy", CSP(nonce))
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), nonceKey{}, nonce)))
	})
}

// NoStore marks a response as personal: never cached, and varying on
// HX-Request so a fragment and a full page are never confused.
func NoStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Add("Vary", "HX-Request")
		next.ServeHTTP(w, r)
	})
}

// LimitBody caps the request body before anything reads it. A request that
// declares a larger body is refused with 413 at once, so a handler never sees
// it; one that sends more than it declared, or declares nothing, fails when
// the handler reads past the cap.
func LimitBody(max int64, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength > max {
			w.Header().Set("Connection", "close")
			http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
			return
		}
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, max)
		}
		next.ServeHTTP(w, r)
	})
}

func safeMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions
}

// SameOrigin refuses any state-changing request that the browser did not
// send from the app's own pages. origin is the configured public origin, such
// as "https://enquiries.example.org"; it is compared exactly, and the Host
// header is never consulted. The shared sign-in cookie reaches every app on
// the domain, so without this a form on a sibling app, or anywhere else,
// could act as the signed-in user.
func SameOrigin(origin string, refuse func(http.ResponseWriter, *http.Request)) func(http.Handler) http.Handler {
	want := canonicalOrigin(origin)
	if want == "" {
		panic("secure: SameOrigin needs an absolute https or http origin, got " + origin)
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !safeMethod(r.Method) && !SameOriginRequest(r, want) {
				refuse(w, r)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// SameOriginRequest reports whether r came from origin (already canonical).
func SameOriginRequest(r *http.Request, origin string) bool {
	if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" {
		return false
	}
	src := r.Header.Get("Origin")
	if src == "" {
		src = r.Header.Get("Referer")
	}
	if src == "" || src == "null" {
		return false
	}
	return canonicalOrigin(src) == origin
}

// canonicalOrigin reduces a URL to scheme://host[:port], lower-cased, with a
// default port dropped. It returns "" for anything else.
func canonicalOrigin(s string) string {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil || u.Host == "" || u.User != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return ""
	}
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if (u.Scheme == "https" && port == "443") || (u.Scheme == "http" && port == "80") {
		port = ""
	}
	if port != "" {
		host += ":" + port
	}
	return u.Scheme + "://" + host
}

// CanonicalOrigin is canonicalOrigin for callers outside the package.
func CanonicalOrigin(s string) string { return canonicalOrigin(s) }
