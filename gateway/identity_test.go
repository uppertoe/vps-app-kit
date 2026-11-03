package gateway

import (
	"errors"
	"net/http/httptest"
	"testing"
)

func TestFromRequest(t *testing.T) {
	cases := []struct {
		name    string
		headers map[string][]string
		want    Identity
		err     error
	}{
		{"user with groups", map[string][]string{
			HeaderEmail: {"Ann@RCH.org.au"}, HeaderUser: {"ann@rch.org.au"}, HeaderGroups: {"user, Fellows ,fellows,"},
		}, Identity{Email: "ann@rch.org.au", Name: "ann@rch.org.au", Role: RoleUser, Groups: []string{"fellows"}}, nil},
		{"guest", map[string][]string{HeaderEmail: {"x@gmail.com"}, HeaderGroups: {"guest"}},
			Identity{Email: "x@gmail.com", Role: RoleGuest}, nil},
		{"nothing", map[string][]string{}, Identity{}, ErrNoIdentity},
		{"groups without email", map[string][]string{HeaderGroups: {"admin"}}, Identity{}, ErrNoIdentity},
		{"repeated email", map[string][]string{HeaderEmail: {"a@x.org", "b@x.org"}, HeaderGroups: {"user"}}, Identity{}, ErrRepeatedHeader},
		{"repeated groups", map[string][]string{HeaderEmail: {"a@x.org"}, HeaderGroups: {"user", "admin"}}, Identity{}, ErrRepeatedHeader},
		{"role not first", map[string][]string{HeaderEmail: {"a@x.org"}, HeaderGroups: {"fellows,admin"}}, Identity{}, ErrBadRole},
		{"empty role", map[string][]string{HeaderEmail: {"a@x.org"}, HeaderGroups: {""}}, Identity{}, ErrBadRole},
		{"two @", map[string][]string{HeaderEmail: {"a@gmail.com@rch.org.au"}, HeaderGroups: {"user"}}, Identity{}, ErrBadEmail},
		{"display name", map[string][]string{HeaderEmail: {"Ann <a@x.org>"}, HeaderGroups: {"user"}}, Identity{}, ErrBadEmail},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			for k, vs := range c.headers {
				for _, v := range vs {
					r.Header.Add(k, v)
				}
			}
			got, err := FromRequest(r)
			if !errors.Is(err, c.err) {
				t.Fatalf("err = %v, want %v", err, c.err)
			}
			if err != nil {
				return
			}
			if got.Email != c.want.Email || got.Name != c.want.Name || got.Role != c.want.Role || len(got.Groups) != len(c.want.Groups) {
				t.Fatalf("got %+v, want %+v", got, c.want)
			}
			for i := range got.Groups {
				if got.Groups[i] != c.want.Groups[i] {
					t.Fatalf("groups %v, want %v", got.Groups, c.want.Groups)
				}
			}
		})
	}
}

func TestMembership(t *testing.T) {
	admin := Identity{Email: "a@rch.org.au", Role: RoleAdmin}
	if !admin.InGroup("admin") || !admin.InGroup("ADMIN") {
		t.Fatal("admin role should satisfy the admin group")
	}
	u := Identity{Email: "u@sub.rch.org.au", Role: RoleUser, Groups: []string{"fellows"}}
	if u.InGroup("admin") || u.InGroup("fellow") || !u.InGroup("fellows") {
		t.Fatal("group match must be exact")
	}
	if u.AtDomain("rch.org.au") {
		t.Fatal("a subdomain must not match its parent domain")
	}
	if !u.AtDomain("sub.rch.org.au") {
		t.Fatal("exact domain should match")
	}
}

func TestDevBuildAbsent(t *testing.T) {
	if DevEnabled || DevHandler != nil {
		t.Fatal("the default build must not contain the dev stand-in")
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Cookie", "kit_dev_identity=a%40x.org%7Cadmin")
	if _, err := FromRequest(r); !errors.Is(err, ErrNoIdentity) {
		t.Fatal("a dev cookie must mean nothing outside a dev build")
	}
}

func FuzzFromRequest(f *testing.F) {
	f.Add("a@x.org", "user,a,b")
	f.Add("a@gmail.com@rch.org.au", "admin")
	f.Add("", "guest")
	f.Fuzz(func(t *testing.T, email, groups string) {
		r := httptest.NewRequest("GET", "/", nil)
		r.Header.Set(HeaderEmail, email)
		r.Header.Set(HeaderGroups, groups)
		id, err := FromRequest(r)
		if err != nil {
			return
		}
		if id.Role != RoleAdmin && id.Role != RoleUser && id.Role != RoleGuest {
			t.Fatalf("accepted role %q", id.Role)
		}
		if id.Domain() == "" {
			t.Fatalf("accepted address %q without a domain", id.Email)
		}
	})
}
