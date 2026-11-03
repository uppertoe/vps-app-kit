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
