package access

import (
	"testing"

	"github.com/uppertoe/vps-app-kit/gateway"
)

func TestAllowsMatrix(t *testing.T) {
	admin := gateway.Identity{Email: "boss@elsewhere.org", Role: gateway.RoleAdmin}
	staff := gateway.Identity{Email: "ann@rch.org.au", Role: gateway.RoleUser}
	member := gateway.Identity{Email: "bob@monash.edu", Role: gateway.RoleUser, Groups: []string{"fellows"}}
	other := gateway.Identity{Email: "cat@monash.edu", Role: gateway.RoleUser}
	guest := gateway.Identity{Email: "dan@gmail.com", Role: gateway.RoleGuest}
	guestAtDomain := gateway.Identity{Email: "eve@rch.org.au", Role: gateway.RoleGuest}
	guestInGroup := gateway.Identity{Email: "fay@gmail.com", Role: gateway.RoleGuest, Groups: []string{"fellows"}}

	type row struct {
		id   gateway.Identity
		want bool
	}
	cases := []struct {
		level Level
		rows  []row
	}{
		{SignedIn(), []row{{admin, true}, {staff, true}, {member, true}, {guest, false}, {guestInGroup, false}}},
		{SignedInOrGuest(), []row{{staff, true}, {guest, true}, {guestInGroup, true}}},
		{Domain("rch.org.au"), []row{{staff, true}, {admin, false}, {member, false}, {guestAtDomain, false}}},
		{Group("fellows"), []row{{member, true}, {guestInGroup, true}, {staff, false}, {admin, false}, {guest, false}}},
		{Group("admin"), []row{{admin, true}, {staff, false}}},
		{DomainOrGroup([]string{"rch.org.au"}, []string{"fellows"}), []row{
			{staff, true}, {member, true}, {guestInGroup, true}, {guestAtDomain, false}, {other, false}, {admin, false},
		}},
		{Public("landing page"), []row{{staff, false}}},
		{Webhook("github pushes"), []row{{staff, false}}},
	}
	for _, c := range cases {
		for _, r := range c.rows {
			if got := c.level.Allows(r.id); got != r.want {
				t.Errorf("%s allows %s (%s): got %v, want %v", c.level, r.id.Email, r.id.Role, got, r.want)
			}
		}
	}
}

func TestZeroLevelIsInvalid(t *testing.T) {
	var l Level
	if l.Valid() || l.Allows(gateway.Identity{Email: "a@x.org", Role: gateway.RoleAdmin}) {
		t.Fatal("the zero level must admit nobody")
	}
}

func TestConstructorsRefuseBadInput(t *testing.T) {
	bad := map[string]func(){
		"empty reason":     func() { Public("") },
		"brace in reason":  func() { Public("see {x}") },
		"newline":          func() { Webhook("a\nb") },
		"role as group":    func() { Group("user") },
		"guest as group":   func() { Group("guest") },
		"no groups":        func() { Group() },
		"bad group":        func() { Group("a b") },
		"quote in group":   func() { Group(`a"`) },
		"bad domain":       func() { Domain("rch") },
		"domain with path": func() { Domain("rch.org.au/x") },
	}
	for name, f := range bad {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("expected a panic")
				}
			}()
			f()
		})
	}
}
