package gateway

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const tok = "0123456789abcdef0123456789abcdef"

func newTestClient(t *testing.T, h http.HandlerFunc) *MembersClient {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c, err := NewMembersClient(srv.URL, tok)
	if err != nil {
		t.Fatal(err)
	}
	c.sleep = func(context.Context, time.Duration) error { return nil }
	return c
}

func TestMembers(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/groups/coordinators/members" || r.Header.Get("Authorization") != "Bearer "+tok {
			http.Error(w, `{"error":"x"}`, http.StatusUnauthorized)
			return
		}
		w.Write([]byte(`{"group":"coordinators","members":["A@rch.org.au","b@rch.org.au"],"as_of":"2026-11-03T10:00:00Z"}`))
	})
	got, err := c.Members(context.Background(), "Coordinators")
	if err != nil || strings.Join(got, ",") != "a@rch.org.au,b@rch.org.au" {
		t.Fatalf("%v %v", got, err)
	}
}

func TestMembersErrors(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name  string
		reply func(http.ResponseWriter)
		want  error
	}{
		{"refused group", func(w http.ResponseWriter) { w.WriteHeader(http.StatusForbidden) }, ErrMembersRefused},
		{"bad token", func(w http.ResponseWriter) { w.WriteHeader(http.StatusUnauthorized) }, ErrMembersUnauthorized},
		{"wrong group in reply", func(w http.ResponseWriter) { w.Write([]byte(`{"group":"other","members":[]}`)) }, ErrMembersUnavailable},
		{"null members", func(w http.ResponseWriter) { w.Write([]byte(`{"group":"g","members":null}`)) }, ErrMembersUnavailable},
		{"not an address", func(w http.ResponseWriter) { w.Write([]byte(`{"group":"g","members":["Ann <a@x.org>"]}`)) }, ErrMembersUnavailable},
	}
	for _, tc := range cases {
		c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) { tc.reply(w) })
		if _, err := c.Members(ctx, "g"); !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v, want %v", tc.name, err, tc.want)
		}
	}
}

func TestMembersRetriesThenGivesUp(t *testing.T) {
	calls := 0
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls < 3 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Write([]byte(`{"group":"g","members":[]}`))
	})
	got, err := c.Members(context.Background(), "g")
	if err != nil || got == nil || len(got) != 0 || calls != 3 {
		t.Fatalf("got %v %v after %d calls", got, err, calls)
	}
	always := newTestClient(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusServiceUnavailable) })
	if _, err := always.Members(context.Background(), "g"); !errors.Is(err, ErrMembersUnavailable) {
		t.Fatalf("err = %v", err)
	}
}

func TestMembersConfiguration(t *testing.T) {
	off, err := NewMembersClient("", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := off.Members(context.Background(), "g"); !errors.Is(err, ErrMembersNotConfigured) {
		t.Fatal("an unconfigured client must say so")
	}
	for name, args := range map[string][2]string{
		"https":       {"https://auth:8081", tok},
		"path":        {"http://auth:8081/v1", tok},
		"short token": {"http://auth:8081", "short"},
		"credentials": {"http://u:p@auth:8081", tok},
		"url only":    {"http://auth:8081", ""},
	} {
		if _, err := NewMembersClient(args[0], args[1]); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := off.Members(context.Background(), "a/b"); err == nil {
		t.Error("a group with a slash must be refused")
	}
}

func TestMembersRefusesPublicAddress(t *testing.T) {
	c, err := NewMembersClient("http://1.1.1.1:8081", tok)
	if err != nil {
		t.Fatal(err)
	}
	c.sleep = func(context.Context, time.Duration) error { return nil }
	if _, err := c.Members(context.Background(), "g"); err == nil || !strings.Contains(err.Error(), "not an internal address") {
		t.Fatalf("err = %v", err)
	}
}
