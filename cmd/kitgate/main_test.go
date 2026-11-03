package main

import "testing"

func TestLevelsAndAdmission(t *testing.T) {
	staff := &person{email: "s@rch.org.au", role: "user"}
	member := &person{email: "m@example.net", role: "user", groups: []string{"fellows"}}
	admin := &person{email: "b@example.net", role: "admin"}
	guest := &person{email: "g@x.example", role: "guest"}
	anon := &person{}
	cases := []struct {
		level string
		p     *person
		want  bool
	}{
		{"public (landing page)", anon, true},
		{"signed in", anon, false},
		{"signed in", guest, false},
		{"signed in", staff, true},
		{"signed in or guest", guest, true},
		{"domain rch.org.au", staff, true},
		{"domain rch.org.au", admin, false},
		{"group fellows", member, true},
		{"group fellows", staff, false},
		{"group admin", admin, true},
		{"domain rch.org.au or group fellows", member, true},
		{"domain rch.org.au or group fellows", staff, true},
		{"domain rch.org.au or group fellows", admin, false},
	}
	for _, c := range cases {
		if got := c.p.admitted(parseLevel(c.level)); got != c.want {
			t.Errorf("%q admits %s (%s): %v, want %v", c.level, c.p.email, c.p.role, got, c.want)
		}
	}
	if parseLevel("something new").kind != "unknown" {
		t.Error("an unknown level must not be guessed")
	}
}

func TestConcrete(t *testing.T) {
	for in, want := range map[string]string{"/{$}": "/", "/p/{id}/edit": "/p/x/edit", "/files/{rest...}": "/files/x", "/notes": "/notes"} {
		if got := concrete(in); got != want {
			t.Errorf("concrete(%q) = %q, want %q", in, got, want)
		}
	}
}
