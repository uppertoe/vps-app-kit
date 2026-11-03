package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/uppertoe/vps-app-kit/sqlitex"
)

var key = bytes.Repeat([]byte("k"), 32)

func standardRequest(id string, ts time.Time, body []byte, k []byte) *http.Request {
	t := strconv.FormatInt(ts.Unix(), 10)
	m := hmac.New(sha256.New, k)
	m.Write([]byte(id + "." + t + "."))
	m.Write(body)
	r := httptest.NewRequest("POST", "/hooks/x", bytes.NewReader(body))
	r.Header.Set("webhook-id", id)
	r.Header.Set("webhook-timestamp", t)
	r.Header.Set("webhook-signature", "v1,"+base64.StdEncoding.EncodeToString(m.Sum(nil)))
	return r
}

func setup(t *testing.T) (http.Handler, *int) {
	db, err := sqlitex.Open(filepath.Join(t.TempDir(), "w.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	rp, err := NewSQLiteReplay(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	h := Handler(NewStandardWebhooks(key), rp, Options{MaxBody: 1024}, func(w http.ResponseWriter, r *http.Request, body []byte) {
		calls++
		w.WriteHeader(202)
	})
	return h, &calls
}

func serve(h http.Handler, r *http.Request) int {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w.Code
}

func TestStandardWebhooks(t *testing.T) {
	h, calls := setup(t)
	now := time.Now()
	body := []byte(`{"ok":true}`)

	if c := serve(h, standardRequest("msg_1", now, body, key)); c != 202 || *calls != 1 {
		t.Fatalf("valid delivery: %d, calls %d", c, *calls)
	}
	if c := serve(h, standardRequest("msg_1", now, body, key)); c != 200 || *calls != 1 {
		t.Fatalf("replay must be acknowledged but not processed: %d, calls %d", c, *calls)
	}
	cases := map[string]*http.Request{
		"wrong key": standardRequest("msg_2", now, body, bytes.Repeat([]byte("x"), 32)),
		"stale":     standardRequest("msg_3", now.Add(-10*time.Minute), body, key),
		"future":    standardRequest("msg_4", now.Add(10*time.Minute), body, key),
		"oversized": standardRequest("msg_5", now, bytes.Repeat([]byte("a"), 2048), key),
		"unsigned":  httptest.NewRequest("POST", "/hooks/x", bytes.NewReader(body)),
	}
	tampered := standardRequest("msg_6", now, body, key)
	tampered.Body = httpBody(`{"ok":false}`)
	cases["tampered body"] = tampered
	for name, r := range cases {
		if c := serve(h, r); c != 401 {
			t.Errorf("%s: status %d, want 401", name, c)
		}
	}
	if *calls != 1 {
		t.Fatalf("a refused delivery reached the handler (%d calls)", *calls)
	}
	if c := serve(h, httptest.NewRequest("GET", "/hooks/x", nil)); c != 405 {
		t.Errorf("GET: %d", c)
	}
}

func TestRefusalsAreRateLimited(t *testing.T) {
	h, _ := setup(t)
	var last int
	for i := 0; i < 40; i++ {
		last = serve(h, httptest.NewRequest("POST", "/hooks/x", strings.NewReader("x")))
	}
	if last != 429 {
		t.Fatalf("after 40 refusals the status is %d, want 429", last)
	}
}

func TestGitHub(t *testing.T) {
	v := NewGitHub(key)
	body := []byte(`{"zen":"x"}`)
	m := hmac.New(sha256.New, key)
	m.Write(body)
	h := http.Header{}
	h.Set("X-GitHub-Delivery", "d1")
	h.Set("X-Hub-Signature-256", "sha256="+hex.EncodeToString(m.Sum(nil)))
	if id, err := v.Verify(h, body, time.Now()); err != nil || id != "d1" {
		t.Fatalf("valid: %q %v", id, err)
	}
	if _, err := v.Verify(h, []byte(`{"zen":"y"}`), time.Now()); err == nil {
		t.Fatal("tampered body accepted")
	}
}

func TestShortSecretRefused(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected a panic")
		}
	}()
	NewGitHub([]byte("short"))
}

func httpBody(s string) *readCloser { return &readCloser{strings.NewReader(s)} }

type readCloser struct{ *strings.Reader }

func (readCloser) Close() error { return nil }

// A delivery whose handler fails stays retryable: the retry is processed.
// Only a successful delivery is remembered.
func TestFailedDeliveryIsRetried(t *testing.T) {
	db, err := sqlitex.Open(filepath.Join(t.TempDir(), "w.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rp, err := NewSQLiteReplay(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	calls, fail, explode := 0, true, false
	h := Handler(NewStandardWebhooks(key), rp, Options{}, func(w http.ResponseWriter, r *http.Request, body []byte) {
		calls++
		if explode {
			panic("handler bug")
		}
		if fail {
			http.Error(w, "database unavailable", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	})
	now := time.Now()
	body := []byte(`{}`)
	if c := serve(h, standardRequest("msg_r", now, body, key)); c != 500 || calls != 1 {
		t.Fatalf("first attempt: %d, calls %d", c, calls)
	}
	// A panic must not mark the delivery done either.
	explode = true
	func() {
		defer func() { _ = recover() }()
		serve(h, standardRequest("msg_r", now, body, key))
	}()
	explode, fail = false, false
	if c := serve(h, standardRequest("msg_r", now, body, key)); c != 202 || calls != 3 {
		t.Fatalf("retry after failures: %d, calls %d (the retry must be processed)", c, calls)
	}
	if c := serve(h, standardRequest("msg_r", now, body, key)); c != 200 || calls != 3 {
		t.Fatalf("replay after success: %d, calls %d (must not be processed again)", c, calls)
	}
}

// A delivery already being processed is answered 503, and an abandoned
// claim (the process died) can be taken again once its lease runs out.
func TestClaimsAndLeases(t *testing.T) {
	db, err := sqlitex.Open(filepath.Join(t.TempDir(), "w.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	rp, err := NewSQLiteReplay(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	if c, err := rp.Claim(ctx, "a", time.Minute); err != nil || c != Claimed {
		t.Fatalf("first claim: %v %v", c, err)
	}
	if c, _ := rp.Claim(ctx, "a", time.Minute); c != Busy {
		t.Fatalf("second claim while processing: %v", c)
	}
	if c, _ := rp.Claim(ctx, "b", -time.Second); c != Claimed {
		t.Fatal("claim b")
	}
	if c, _ := rp.Claim(ctx, "b", time.Minute); c != Claimed {
		t.Fatalf("an expired claim must be claimable again, got %v", c)
	}
	if err := rp.Complete(ctx, "a", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if c, _ := rp.Claim(ctx, "a", time.Minute); c != Done {
		t.Fatalf("a completed delivery: %v", c)
	}
	if err := rp.Release(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	if c, _ := rp.Claim(ctx, "a", time.Minute); c != Done {
		t.Fatal("Release must never forget a completed delivery")
	}
}

type untilReplay struct{ until time.Time }

func (u *untilReplay) Claim(context.Context, string, time.Duration) (Claim, error) {
	return Claimed, nil
}
func (u *untilReplay) Complete(_ context.Context, _ string, until time.Time) error {
	u.until = until
	return nil
}
func (u *untilReplay) Release(context.Context, string) error { return nil }

// GitHub signs no timestamp, so its deliveries are remembered for at least
// 90 days however short the configured window.
func TestGitHubRemembersLonger(t *testing.T) {
	rp := &untilReplay{}
	h := Handler(NewGitHub(key), rp, Options{RememberFor: time.Hour}, func(w http.ResponseWriter, r *http.Request, b []byte) {})
	body := []byte("{}")
	m := hmac.New(sha256.New, key)
	m.Write(body)
	r := httptest.NewRequest("POST", "/hooks/gh", bytes.NewReader(body))
	r.Header.Set("X-GitHub-Delivery", "d1")
	r.Header.Set("X-Hub-Signature-256", "sha256="+hex.EncodeToString(m.Sum(nil)))
	if c := serve(h, r); c != 200 {
		t.Fatalf("status %d", c)
	}
	if time.Until(rp.until) < 89*24*time.Hour {
		t.Fatalf("remembered only until %v", rp.until)
	}
}
