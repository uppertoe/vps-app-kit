//go:build dev

package gateway

import (
	"html/template"
	"net/http"
	"net/url"
	"strings"
)

// DevEnabled reports whether this binary contains the dev stand-in. Only a
// binary built with "-tags dev" (make run) does.
const DevEnabled = true

const devCookie = "kit_dev_identity"

// devIdentity reads the identity chosen on /dev/identity. It is consulted
// only when the request carries no Remote-* headers at all.
func devIdentity(r *http.Request) (Identity, bool) {
	c, err := r.Cookie(devCookie)
	if err != nil {
		return Identity{}, false
	}
	v, err := url.QueryUnescape(c.Value)
	if err != nil {
		return Identity{}, false
	}
	email, groups, _ := strings.Cut(v, "|")
	id, err := parse(strings.ToLower(strings.TrimSpace(email)), "", groups)
	if err != nil {
		return Identity{}, false
	}
	id.Dev = true
	return id, true
}

var devPage = template.Must(template.New("dev").Parse(`<!doctype html>
<meta charset="utf-8"><title>Choose a test identity</title>
<h1>Choose a test identity</h1>
<p>This page exists only in a development build.</p>
<form method="post" action="/dev/identity">
<input type="hidden" name="next" value="{{.Next}}">
<p><label>Email <input name="email" value="staff@example.org"></label></p>
<p><label>Remote-Groups <input name="groups" value="user"></label></p>
<p>The role comes first (admin, user or guest), then any groups.</p>
<p><button>Continue</button></p>
</form>
<form method="post" action="/dev/identity"><input type="hidden" name="clear" value="1"><button>Sign out</button></form>`))

// DevHandler serves /dev/identity. The router mounts it only in dev builds.
var DevHandler http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		if r.FormValue("clear") != "" {
			http.SetCookie(w, &http.Cookie{Name: devCookie, Path: "/", MaxAge: -1})
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}
		v := strings.TrimSpace(r.FormValue("email")) + "|" + strings.TrimSpace(r.FormValue("groups"))
		http.SetCookie(w, &http.Cookie{Name: devCookie, Value: url.QueryEscape(v), Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode})
		next := r.FormValue("next")
		if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") {
			next = "/"
		}
		http.Redirect(w, r, next, http.StatusSeeOther)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = devPage.Execute(w, map[string]string{"Next": r.URL.Query().Get("next")})
})
