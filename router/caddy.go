package router

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/uppertoe/vps-app-kit/access"
)

// Site describes where the app is served, for the generated snippet.
type Site struct {
	// Name is the app's folder and service name under apps/ in the server
	// repo, such as "fellows".
	Name string
	// Host is the site address, such as "enquiries.{$DOMAIN}".
	Host string
	// Port is the port the container listens on. Default 8080.
	Port int
	// MemberGroups are the groups the app reads from the gateway's members
	// endpoint (app.yaml's members). The snippet carries them as a
	// "scaffold-members" marker, from which the server's route renderer
	// creates the app's private network to the gateway.
	MemberGroups []string
}

var siteNameRe = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

// caddyMatch is one generated handle block.
type caddyMatch struct {
	paths []string // Caddy path matcher values
	level access.Level
	key   string // the literal prefix, for ordering
	exact bool
	from  []string
}

// Caddy renders the app's .caddy snippet. Every registered path gets a named
// matcher and a handle block with its level's guard; the blocks are ordered
// most specific first, as Go's ServeMux chooses; and a final handle answers
// 404 for any path the app did not register, so nothing undeclared reaches
// the container. It returns an error when two routes would share a Caddy
// matcher with different levels, which Go can tell apart and Caddy cannot.
func (rt *Router) Caddy(site Site) (string, error) {
	if !siteNameRe.MatchString(site.Name) {
		return "", fmt.Errorf("router: site name %q must be lower-case letters, digits and hyphens", site.Name)
	}
	if site.Host == "" || strings.ContainsAny(site.Host, " \t\r\n\"") {
		return "", fmt.Errorf("router: site host %q is not a single address", site.Host)
	}
	if site.Port == 0 {
		site.Port = 8080
	}
	upstream := fmt.Sprintf("%s:%d", site.Name, site.Port)

	byKey := map[string]*caddyMatch{}
	for _, r := range rt.Routes() {
		paths, key, exact := caddyPaths(r.Path)
		// Exact paths are told apart by the whole path; prefixes by their
		// literal part, so "/p/" and "/p/{id}" land in one block.
		id := "prefix " + key
		if exact {
			id = "exact " + key
		}
		if m, ok := byKey[id]; ok {
			if !m.level.Equal(r.Level) {
				return "", fmt.Errorf("router: %s (%s) and %s (%s) both become Caddy %s; give them distinct literal prefixes",
					m.from[0], m.level, r.Pattern, r.Level, id)
			}
			for _, p := range paths {
				if !contains(m.paths, p) {
					m.paths = append(m.paths, p)
				}
			}
			m.from = append(m.from, r.Pattern)
			continue
		}
		byKey[id] = &caddyMatch{paths: paths, level: r.Level, key: key, exact: exact, from: []string{r.Pattern}}
	}
	matches := make([]*caddyMatch, 0, len(byKey))
	for _, m := range byKey {
		matches = append(matches, m)
	}
	sort.Slice(matches, func(i, j int) bool {
		a, b := matches[i], matches[j]
		if a.exact != b.exact {
			return a.exact
		}
		if len(a.key) != len(b.key) {
			return len(a.key) > len(b.key)
		}
		return a.key < b.key
	})

	var b strings.Builder
	w := func(depth int, s string) { b.WriteString(strings.Repeat("\t", depth) + s + "\n") }
	w(0, "# Generated from the app's route list by vps-app-kit. Do not edit:")
	w(0, "# change the routes in the app, then run make generate.")
	w(0, "# Keep comments free of braces: the server's route renderer counts them.")
	if len(site.MemberGroups) > 0 {
		for _, g := range site.MemberGroups {
			if !regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`).MatchString(g) {
				return "", fmt.Errorf("router: member group %q is not a group name", g)
			}
		}
		w(0, "# scaffold-members: "+strings.Join(site.MemberGroups, " ")+" -- reads these groups' members from the gateway")
	}
	w(0, site.Host+" {")
	for i, m := range matches {
		name := fmt.Sprintf("@r%d", i+1)
		w(1, "# "+commentSafe(strings.Join(m.from, ", "))+": "+m.level.String())
		w(1, name+" path "+strings.Join(m.paths, " "))
		w(1, "handle "+name+" {")
		for _, line := range m.level.CaddyLines(upstream, rt.opts.MaxWebhookBody) {
			w(2, line)
		}
		w(1, "}")
	}
	w(1, "# Any path the app did not register.")
	w(1, "handle {")
	w(2, "respond 404")
	w(1, "}")
	w(0, "}")
	out := b.String()
	if err := checkComments(out); err != nil {
		return "", err
	}
	return out, nil
}

// caddyPaths turns a ServeMux path into Caddy path matcher values. A literal
// path stays exact; "/x/" (a subtree) becomes "/x" and "/x/*"; a path with a
// wildcard segment is cut at the first wildcard and becomes a prefix. key is
// the literal part, used to order the blocks.
func caddyPaths(path string) (paths []string, key string, exact bool) {
	if strings.HasSuffix(path, "/{$}") {
		p := strings.TrimSuffix(path, "{$}")
		return []string{p}, p, true
	}
	if i := strings.Index(path, "{"); i >= 0 {
		prefix := path[:i]
		if !strings.HasSuffix(prefix, "/") {
			prefix = prefix[:strings.LastIndex(prefix, "/")+1]
		}
		return []string{prefix + "*"}, prefix, false
	}
	if strings.HasSuffix(path, "/") {
		if path == "/" {
			return []string{"/*"}, "/", false
		}
		return []string{strings.TrimSuffix(path, "/"), path + "*"}, path, false
	}
	return []string{path}, path, true
}

func checkComments(s string) error {
	for i, line := range strings.Split(s, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "#") && strings.ContainsAny(t, "{}") {
			return fmt.Errorf("router: generated line %d is a comment containing a brace: %s", i+1, t)
		}
	}
	return nil
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// commentSafe replaces the braces of ServeMux wildcards, which a comment in
// a .caddy file must not contain.
func commentSafe(s string) string {
	return strings.NewReplacer("{", "<", "}", ">").Replace(s)
}
