// Package access defines the only access levels a route can have.
//
// Each level corresponds to exactly one Caddy guard from the gateway's
// snippet catalogue (apps/auth/auth.caddy in a server repo), so the app's own
// check and Caddy's check always ask the same question:
//
//	Public               strip_public         anyone; the app receives no identity
//	Webhook              strip_public         a signed delivery; no identity
//	SignedIn             protected            any signed-in user except a guest
//	SignedInOrGuest      protected_open       any signed-in user, guests included
//	Domain(d...)         protected_domains    users at one of the domains
//	Group(g...)          protected_groups     members of one of the groups
//	DomainOrGroup(d, g)  protected_access     either of the two above
//
// A Level can be made only by these constructors, so a route without a
// level, or with a level outside this list, does not compile.
package access

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/uppertoe/vps-app-kit/gateway"
)

type kind int

const (
	kindPublic kind = iota + 1
	kindWebhook
	kindSignedIn
	kindSignedInOrGuest
	kindDomain
	kindGroup
	kindDomainOrGroup
)

// Level is a route's access level. The zero Level is invalid and the router
// refuses it.
type Level struct {
	k       kind
	domains []string
	groups  []string
	reason  string
}

var (
	domainRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$`)
	groupRe  = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)
)

// Public admits anyone. The reason is required: it becomes the
// "scaffold-lint: public" marker in the generated Caddy snippet and the
// server's who-can-reach-what table.
func Public(reason string) Level { return Level{k: kindPublic, reason: mustReason(reason)} }

// Webhook admits deliveries from an outside service. The route must verify a
// signature (package webhook); the gateway is not involved.
func Webhook(reason string) Level { return Level{k: kindWebhook, reason: mustReason(reason)} }

// SignedIn admits any signed-in user who is not a guest.
func SignedIn() Level { return Level{k: kindSignedIn} }

// SignedInOrGuest also admits guests from open registration. Use it only on
// an app whose host is listed in the gateway's OPEN_REGISTRATION_HOSTS.
func SignedInOrGuest() Level { return Level{k: kindSignedInOrGuest} }

// Domain admits users whose address is at one of the domains, compared
// exactly. Guests are refused, as the gateway's domain guard refuses them.
func Domain(domains ...string) Level {
	return Level{k: kindDomain, domains: mustList(domains, domainRe, "domain")}
}

// Group admits members of any of the groups. The gateway also admits a guest
// an administrator has placed in the group, and a break-glass card whose
// target is the group. "admin" means the gateway's admin role.
func Group(groups ...string) Level {
	return Level{k: kindGroup, groups: mustGroups(groups)}
}

// DomainOrGroup admits users at one of the domains or in one of the groups.
func DomainOrGroup(domains []string, groups []string) Level {
	return Level{k: kindDomainOrGroup, domains: mustList(domains, domainRe, "domain"), groups: mustGroups(groups)}
}

func mustReason(r string) string {
	r = strings.TrimSpace(r)
	if r == "" || strings.ContainsAny(r, "{}\"\r\n") {
		panic(fmt.Sprintf("access: a public or webhook route needs a one-line reason without braces or quotes, got %q", r))
	}
	return r
}

func mustGroups(groups []string) []string {
	out := mustList(groups, groupRe, "group")
	for _, g := range out {
		if g == string(gateway.RoleUser) || g == string(gateway.RoleGuest) {
			panic(fmt.Sprintf("access: %q is a role, not a group; use SignedIn or SignedInOrGuest", g))
		}
	}
	return out
}

func mustList(in []string, re *regexp.Regexp, what string) []string {
	if len(in) == 0 {
		panic("access: at least one " + what + " is required")
	}
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.ToLower(strings.TrimSpace(v))
		if !re.MatchString(v) {
			panic(fmt.Sprintf("access: %q is not a valid %s", v, what))
		}
		out = append(out, v)
	}
	return out
}

// Valid reports whether the level came from a constructor.
func (l Level) Valid() bool { return l.k != 0 }

// Anonymous reports whether the route carries no identity (Public, Webhook).
func (l Level) Anonymous() bool { return l.k == kindPublic || l.k == kindWebhook }

// IsWebhook reports whether the route is a webhook.
func (l Level) IsWebhook() bool { return l.k == kindWebhook }

// Reason is the public or webhook route's stated reason.
func (l Level) Reason() string { return l.reason }

// Allows is the app's own check, made on every request to a gated route.
func (l Level) Allows(id gateway.Identity) bool {
	switch l.k {
	case kindSignedIn:
		return id.Role == gateway.RoleAdmin || id.Role == gateway.RoleUser
	case kindSignedInOrGuest:
		return id.Role == gateway.RoleAdmin || id.Role == gateway.RoleUser || id.Role == gateway.RoleGuest
	case kindDomain:
		return !id.IsGuest() && id.AtDomain(l.domains...)
	case kindGroup:
		return l.inGroups(id)
	case kindDomainOrGroup:
		return (!id.IsGuest() && id.AtDomain(l.domains...)) || l.inGroups(id)
	}
	return false
}

func (l Level) inGroups(id gateway.Identity) bool {
	for _, g := range l.groups {
		if id.InGroup(g) {
			return true
		}
	}
	return false
}

// Equal reports whether two levels admit the same people.
func (l Level) Equal(o Level) bool {
	return l.k == o.k && strings.Join(l.domains, " ") == strings.Join(o.domains, " ") &&
		strings.Join(l.groups, " ") == strings.Join(o.groups, " ")
}

// String describes the level for route listings and error messages.
func (l Level) String() string {
	switch l.k {
	case kindPublic:
		return "public (" + l.reason + ")"
	case kindWebhook:
		return "webhook (" + l.reason + ")"
	case kindSignedIn:
		return "signed in"
	case kindSignedInOrGuest:
		return "signed in or guest"
	case kindDomain:
		return "domain " + strings.Join(l.domains, " ")
	case kindGroup:
		return "group " + strings.Join(l.groups, " ")
	case kindDomainOrGroup:
		return "domain " + strings.Join(l.domains, " ") + " or group " + strings.Join(l.groups, " ")
	}
	return "invalid"
}

// CaddyLines returns the body of the Caddy handle block that enforces the
// level in front of upstream (host:port), one line per element, unindented.
func (l Level) CaddyLines(upstream string, maxWebhookBytes int64) []string {
	q := func(xs []string) string { return `"` + strings.Join(xs, " ") + `"` }
	switch l.k {
	case kindPublic:
		return []string{
			"# scaffold-lint: public -- " + l.reason,
			"reverse_proxy " + upstream + " {",
			"\timport strip_public",
			"}",
		}
	case kindWebhook:
		return []string{
			"# scaffold-lint: public -- webhook: " + l.reason,
			"request_body {",
			fmt.Sprintf("\tmax_size %d", maxWebhookBytes),
			"}",
			"reverse_proxy " + upstream + " {",
			"\timport strip_public",
			"}",
		}
	case kindSignedIn:
		return []string{"import protected " + upstream}
	case kindSignedInOrGuest:
		return []string{"import protected_open " + upstream}
	case kindDomain:
		return []string{"import protected_domains " + q(l.domains) + " " + upstream}
	case kindGroup:
		return []string{"import protected_groups " + q(l.groups) + " " + upstream}
	case kindDomainOrGroup:
		return []string{"import protected_access " + q(l.domains) + " " + q(l.groups) + " " + upstream}
	}
	panic("access: invalid level")
}
