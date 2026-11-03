// Package router registers an app's routes, each with an access level, and
// enforces that level on every request. It also generates the app's Caddy
// snippet from the same list (see caddy.go), so the app's gate and Caddy's
// gate are built from one declaration and cannot disagree.
//
// On a gated route the router reads the identity headers, refuses the
// request if they are missing, repeated or malformed, and refuses it again
// unless the level admits the identity, whatever Caddy has already decided.
// On a public or webhook route it deletes the identity headers before the
// handler runs, so a handler there can never act on a forged identity.
package router

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync/atomic"

	"github.com/uppertoe/vps-app-kit/access"
	"github.com/uppertoe/vps-app-kit/gateway"
	"github.com/uppertoe/vps-app-kit/secure"
)

// Options configure a Router.
type Options struct {
	// PublicOrigin is the app's address as browsers see it, such as
	// "https://enquiries.example.org". Writes from any other origin are
	// refused. Required.
	PublicOrigin string
	// MaxBody caps every request body except a webhook's. Default 64 KiB.
	MaxBody int64
	// MaxWebhookBody caps a webhook body, in the app and in Caddy.
	// Default 256 KiB.
	MaxWebhookBody int64
	// Deny writes the refusal page. status is 401 (no usable identity),
	// 403 (identity not admitted, or a cross-site write). The default
	// writes plain text.
	Deny func(w http.ResponseWriter, r *http.Request, status int)
}

// Route is one registered route.
type Route struct {
	Pattern string // as given, such as "GET /admin/{id}"
	Method  string // "" when the pattern names none
	Path    string // the path part of the pattern
	Level   access.Level
}

// Router is an http.Handler.
type Router struct {
	mux    *http.ServeMux
	opts   Options
	routes []Route
	levels map[string]access.Level // path -> level
	// sealed is set by the first request; registering a route after that
	// panics. Atomic, because requests are served concurrently.
	sealed atomic.Bool
}

// New returns a Router with /healthz already registered as public.
func New(opts Options) *Router {
	if !secure.ExactOrigin(opts.PublicOrigin) {
		panic("router: Options.PublicOrigin must be an origin alone, such as https://app.example.org, with no path, query or credentials")
	}
	if opts.MaxBody == 0 {
		opts.MaxBody = 64 << 10
	}
	if opts.MaxWebhookBody == 0 {
		opts.MaxWebhookBody = 256 << 10
	}
	if opts.Deny == nil {
		opts.Deny = func(w http.ResponseWriter, r *http.Request, status int) {
			http.Error(w, http.StatusText(status), status)
		}
	}
	rt := &Router{mux: http.NewServeMux(), opts: opts, levels: map[string]access.Level{}}
	rt.HandleFunc("GET /healthz", access.Public("container health check"), func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte("ok\n"))
	})
	if gateway.DevHandler != nil {
		// Dev builds only. Not a Route, so it never reaches the Caddy snippet.
		rt.mux.Handle("/dev/identity", secure.Headers(gateway.DevHandler))
	}
	return rt
}

// HandleFunc is Handle for a function.
func (rt *Router) HandleFunc(pattern string, level access.Level, h http.HandlerFunc) {
	rt.Handle(pattern, level, h)
}

// Handle registers h at pattern (Go's ServeMux syntax, without a host) with
// the given access level. A path has exactly one level whatever the method,
// because Caddy matches on the path alone. It panics on a misuse, so the
// mistake stops the app at start-up rather than at the first request.
func (rt *Router) Handle(pattern string, level access.Level, h http.Handler) {
	if rt.sealed.Load() {
		panic("router: Handle after ServeHTTP")
	}
	if !level.Valid() {
		panic("router: " + pattern + " has no access level")
	}
	if _, verified := h.(interface{ VerifiesSignatures() }); level.IsWebhook() && !verified {
		panic("router: " + pattern + " is a webhook route, so its handler must come from webhook.Handler, which verifies every delivery")
	}
	method, path := splitPattern(pattern)
	if prev, ok := rt.levels[path]; ok && !prev.Equal(level) {
		panic(fmt.Sprintf("router: %s is %s, but %s was already registered as %s; a path has one access level", pattern, level, path, prev))
	}
	if strings.HasPrefix(path, "/dev/") {
		panic("router: /dev/ is reserved for the dev stand-in")
	}
	rt.levels[path] = level
	rt.routes = append(rt.routes, Route{Pattern: pattern, Method: method, Path: path, Level: level})
	rt.mux.Handle(pattern, rt.wrap(level, h))
}

func splitPattern(p string) (method, path string) {
	p = strings.TrimSpace(p)
	if i := strings.IndexAny(p, " \t"); i >= 0 {
		method, path = p[:i], strings.TrimSpace(p[i+1:])
	} else {
		path = p
	}
	if !strings.HasPrefix(path, "/") {
		panic("router: pattern " + p + " must not name a host and must start with /")
	}
	return method, path
}

func (rt *Router) refuse(status int) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) { rt.opts.Deny(w, r, status) }
}

// wrap builds the chain for one route. Read it top to bottom: headers, body
// cap, then the level's own checks, then the handler.
func (rt *Router) wrap(level access.Level, h http.Handler) http.Handler {
	var inner http.Handler
	switch {
	case level.IsWebhook():
		// No same-origin check (an outside service is the sender) and no
		// identity; the handler must verify the signature (package webhook).
		inner = secure.LimitBody(rt.opts.MaxWebhookBody, stripIdentity(h))
	case level.Anonymous():
		inner = secure.LimitBody(rt.opts.MaxBody,
			secure.SameOrigin(rt.opts.PublicOrigin, rt.refuse(http.StatusForbidden))(stripIdentity(h)))
	default:
		inner = secure.NoStore(secure.LimitBody(rt.opts.MaxBody,
			secure.SameOrigin(rt.opts.PublicOrigin, rt.refuse(http.StatusForbidden))(rt.gate(level, h))))
	}
	return secure.Headers(inner)
}

func stripIdentity(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gateway.StripHeaders(r)
		h.ServeHTTP(w, r)
	})
}

func (rt *Router) gate(level access.Level, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, err := gateway.FromRequest(r)
		if err != nil {
			rt.opts.Deny(w, r, http.StatusUnauthorized)
			return
		}
		if !level.Allows(id) {
			rt.opts.Deny(w, r, http.StatusForbidden)
			return
		}
		h.ServeHTTP(w, r.WithContext(gateway.WithIdentity(r.Context(), id)))
	})
}

// ServeHTTP dispatches to the registered routes.
func (rt *Router) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !rt.sealed.Load() {
		rt.sealed.Store(true)
	}
	rt.mux.ServeHTTP(w, r)
}

// Routes returns the registered routes sorted by path then method.
func (rt *Router) Routes() []Route {
	out := append([]Route(nil), rt.routes...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].Method < out[j].Method
	})
	return out
}

// Table prints the routes as "method path level" lines, for `-routes`.
func (rt *Router) Table() string {
	var b strings.Builder
	for _, r := range rt.Routes() {
		m := r.Method
		if m == "" {
			m = "*"
		}
		fmt.Fprintf(&b, "%-6s %-40s %s\n", m, r.Path, r.Level)
	}
	return b.String()
}
