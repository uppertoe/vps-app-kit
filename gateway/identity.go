// Package gateway reads the identity that the platform's sign-in gateway
// passes to an app.
//
// Caddy asks the gateway about every request to a gated route. On success the
// gateway answers with three headers, which Caddy copies onto the request it
// forwards to the app, after deleting any copies the client sent:
//
//	Remote-User    the signed-in address (the gateway sets it to the email)
//	Remote-Email   the signed-in address
//	Remote-Groups  a comma-separated set: the role first (admin, user or
//	               guest), then the groups the person belongs to
//
// The headers are trustworthy only because Caddy is the sole way into the
// container and Caddy replaces them. An app therefore reads them only on
// gated routes; on a public or webhook route the router deletes them before
// the handler runs (see package router).
package gateway

import (
	"context"
	"errors"
	"net/http"
	"net/mail"
	"strings"
)

// Role is the first element of Remote-Groups.
type Role string

const (
	RoleAdmin Role = "admin"
	RoleUser  Role = "user"
	RoleGuest Role = "guest"
)

// Header names, exported so tests and the dev stand-in use the same spelling.
const (
	HeaderUser   = "Remote-User"
	HeaderEmail  = "Remote-Email"
	HeaderGroups = "Remote-Groups"
)

// Identity is who the gateway says is making the request.
type Identity struct {
	Email string
	Name  string
	Role  Role
	// Groups are the gateway groups after the role, lower-cased, in the
	// order sent. The role itself is not repeated here.
	Groups []string
	// Dev is true when the identity came from the local dev stand-in, which
	// exists only in binaries built with the "dev" tag.
	Dev bool
}

// Errors returned by FromRequest. Each means the request must be refused.
var (
	ErrNoIdentity     = errors.New("gateway: no identity on request")
	ErrRepeatedHeader = errors.New("gateway: identity header sent more than once")
	ErrBadRole        = errors.New("gateway: unknown role in Remote-Groups")
	ErrBadEmail       = errors.New("gateway: Remote-Email is not a single address")
)

// FromRequest parses the identity headers. It refuses a request that carries
// more than one value for any of them, rather than picking one: Caddy sets
// each exactly once, so a second value means something else added it.
func FromRequest(r *http.Request) (Identity, error) {
	for _, h := range []string{HeaderUser, HeaderEmail, HeaderGroups} {
		if len(r.Header.Values(h)) > 1 {
			return Identity{}, ErrRepeatedHeader
		}
	}
	email := strings.ToLower(strings.TrimSpace(r.Header.Get(HeaderEmail)))
	groups := r.Header.Get(HeaderGroups)
	if email == "" && groups == "" {
		if id, ok := devIdentity(r); ok {
			return id, nil
		}
		return Identity{}, ErrNoIdentity
	}
	return parse(email, strings.TrimSpace(r.Header.Get(HeaderUser)), groups)
}

func parse(email, name, groups string) (Identity, error) {
	if email == "" {
		return Identity{}, ErrNoIdentity
	}
	if _, ok := domainOf(email); !ok {
		return Identity{}, ErrBadEmail
	}
	parts := strings.Split(groups, ",")
	role := Role(strings.ToLower(strings.TrimSpace(parts[0])))
	switch role {
	case RoleAdmin, RoleUser, RoleGuest:
	default:
		return Identity{}, ErrBadRole
	}
	id := Identity{Email: email, Name: name, Role: role}
	seen := map[string]bool{}
	for _, g := range parts[1:] {
		g = strings.ToLower(strings.TrimSpace(g))
		if g == "" || seen[g] {
			continue
		}
		seen[g] = true
		id.Groups = append(id.Groups, g)
	}
	return id, nil
}

// IsGuest reports whether this is a stranger admitted by open registration.
func (id Identity) IsGuest() bool { return id.Role == RoleGuest }

// IsAdmin reports whether the gateway gave this person its admin role.
func (id Identity) IsAdmin() bool { return id.Role == RoleAdmin }

// InGroup reports exact membership. "admin" matches the admin role, as the
// gateway's own groups=admin policy does.
func (id Identity) InGroup(group string) bool {
	group = strings.ToLower(strings.TrimSpace(group))
	if group == "" {
		return false
	}
	if group == string(RoleAdmin) && id.Role == RoleAdmin {
		return true
	}
	for _, g := range id.Groups {
		if g == group {
			return true
		}
	}
	return false
}

// Domain returns the lower-cased domain of the address, or "" when the
// address does not parse as exactly one address.
func (id Identity) Domain() string {
	d, _ := domainOf(id.Email)
	return d
}

// AtDomain reports whether the address is at one of the given domains,
// compared exactly (a subdomain does not match).
func (id Identity) AtDomain(domains ...string) bool {
	d := id.Domain()
	if d == "" {
		return false
	}
	for _, want := range domains {
		if d == strings.ToLower(strings.TrimSpace(want)) {
			return true
		}
	}
	return false
}

// Display is the name to show, falling back to the address.
func (id Identity) Display() string {
	if id.Name != "" && !strings.Contains(id.Name, "@") {
		return id.Name
	}
	return id.Email
}

// domainOf accepts exactly one bare address with exactly one "@", so that
// "a@gmail.com@rch.org.au" or a display-name form is not read as a domain.
func domainOf(email string) (string, bool) {
	a, err := mail.ParseAddress(email)
	if err != nil || a.Name != "" || !strings.EqualFold(a.Address, email) {
		return "", false
	}
	if strings.Count(a.Address, "@") != 1 {
		return "", false
	}
	at := strings.LastIndex(a.Address, "@")
	if at <= 0 || at == len(a.Address)-1 {
		return "", false
	}
	return strings.ToLower(a.Address[at+1:]), true
}

type ctxKey struct{}

// WithIdentity returns a context carrying id. The router calls it; handlers
// read the identity back with From.
func WithIdentity(ctx context.Context, id Identity) context.Context {
	return context.WithValue(ctx, ctxKey{}, id)
}

// From returns the identity the router attached. ok is false on public and
// webhook routes, which carry none.
func From(ctx context.Context) (Identity, bool) {
	id, ok := ctx.Value(ctxKey{}).(Identity)
	return id, ok
}

// StripHeaders deletes every identity header from r. The router calls it on
// public and webhook routes, so that a handler there can never read one.
func StripHeaders(r *http.Request) {
	r.Header.Del(HeaderUser)
	r.Header.Del(HeaderEmail)
	r.Header.Del(HeaderGroups)
}
