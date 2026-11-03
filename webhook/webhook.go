// Package webhook receives signed deliveries from outside services.
//
// A webhook route sits outside the gateway (access.Webhook), so the
// signature is the only thing that admits a delivery. Handler reads the raw
// body under a cap, checks the signature in constant time before anything
// parses the body, refuses a stale timestamp where the scheme carries one,
// and refuses a replayed delivery. Every refusal gets the same response, and
// refusals are rate limited.
package webhook

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// MinSecretBytes is the shortest secret a verifier accepts.
const MinSecretBytes = 32

// ErrInvalid is returned for any delivery that fails verification. The
// reason is logged, never sent to the caller.
var ErrInvalid = errors.New("webhook: invalid delivery")

// Verifier checks one provider's signature scheme and returns the delivery's
// unique ID, for replay protection.
type Verifier interface {
	Verify(h http.Header, body []byte, now time.Time) (id string, err error)
	Name() string
}

func checkSecrets(secrets [][]byte) {
	if len(secrets) == 0 || len(secrets) > 2 {
		panic("webhook: give one secret, or two while rotating")
	}
	for _, s := range secrets {
		if len(s) < MinSecretBytes {
			panic(fmt.Sprintf("webhook: a secret must be at least %d bytes", MinSecretBytes))
		}
	}
}

// StandardWebhooks verifies the Standard Webhooks scheme (webhook-id,
// webhook-timestamp and webhook-signature headers), used by many providers.
// Secrets are the decoded bytes of the provider's "whsec_..." value.
type StandardWebhooks struct {
	secrets   [][]byte
	tolerance time.Duration
}

// NewStandardWebhooks accepts one secret, or two while rotating.
func NewStandardWebhooks(secrets ...[]byte) StandardWebhooks {
	checkSecrets(secrets)
	return StandardWebhooks{secrets: secrets, tolerance: 5 * time.Minute}
}

// DecodeStandardSecret turns "whsec_<base64>" into the key bytes.
func DecodeStandardSecret(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(strings.TrimPrefix(strings.TrimSpace(s), "whsec_"))
}

func (StandardWebhooks) Name() string { return "standard-webhooks" }

func (v StandardWebhooks) Verify(h http.Header, body []byte, now time.Time) (string, error) {
	id, ts, sigs := h.Get("webhook-id"), h.Get("webhook-timestamp"), h.Get("webhook-signature")
	if id == "" || ts == "" || sigs == "" {
		return "", fmt.Errorf("%w: missing header", ErrInvalid)
	}
	secs, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return "", fmt.Errorf("%w: bad timestamp", ErrInvalid)
	}
	if d := now.Sub(time.Unix(secs, 0)); d > v.tolerance || d < -v.tolerance {
		return "", fmt.Errorf("%w: timestamp outside tolerance", ErrInvalid)
	}
	signed := []byte(id + "." + ts + ".")
	signed = append(signed, body...)
	for _, key := range v.secrets {
		m := hmac.New(sha256.New, key)
		m.Write(signed)
		want := m.Sum(nil)
		for _, s := range strings.Fields(sigs) {
			ver, b64, ok := strings.Cut(s, ",")
			if !ok || ver != "v1" {
				continue
			}
			got, err := base64.StdEncoding.DecodeString(b64)
			if err == nil && hmac.Equal(got, want) {
				return id, nil
			}
		}
	}
	return "", fmt.Errorf("%w: signature mismatch", ErrInvalid)
}

// GitHub verifies X-Hub-Signature-256. GitHub signs no timestamp, so replay
// protection rests on X-GitHub-Delivery alone.
type GitHub struct{ secrets [][]byte }

// NewGitHub accepts one secret, or two while rotating.
func NewGitHub(secrets ...[]byte) GitHub {
	checkSecrets(secrets)
	return GitHub{secrets: secrets}
}

func (GitHub) Name() string { return "github" }

func (v GitHub) Verify(h http.Header, body []byte, _ time.Time) (string, error) {
	id := h.Get("X-GitHub-Delivery")
	sig, ok := strings.CutPrefix(h.Get("X-Hub-Signature-256"), "sha256=")
	if id == "" || !ok {
		return "", fmt.Errorf("%w: missing header", ErrInvalid)
	}
	got, err := hex.DecodeString(sig)
	if err != nil {
		return "", fmt.Errorf("%w: bad signature encoding", ErrInvalid)
	}
	for _, key := range v.secrets {
		m := hmac.New(sha256.New, key)
		m.Write(body)
		if hmac.Equal(got, m.Sum(nil)) {
			return id, nil
		}
	}
	return "", fmt.Errorf("%w: signature mismatch", ErrInvalid)
}

// Replay remembers delivery IDs. Remember reports false when id was already
// seen and has not yet expired.
type Replay interface {
	Remember(ctx context.Context, id string, until time.Time) (fresh bool, err error)
}

// SQLiteReplay keeps delivery IDs in the app's database.
type SQLiteReplay struct{ db *sql.DB }

// NewSQLiteReplay creates its table if needed.
func NewSQLiteReplay(ctx context.Context, db *sql.DB) (*SQLiteReplay, error) {
	_, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS kit_webhook_seen (
		id TEXT PRIMARY KEY, expires INTEGER NOT NULL)`)
	return &SQLiteReplay{db: db}, err
}

func (s *SQLiteReplay) Remember(ctx context.Context, id string, until time.Time) (bool, error) {
	now := time.Now().Unix()
	if _, err := s.db.ExecContext(ctx, `DELETE FROM kit_webhook_seen WHERE expires < ?`, now); err != nil {
		return false, err
	}
	res, err := s.db.ExecContext(ctx, `INSERT OR IGNORE INTO kit_webhook_seen(id, expires) VALUES (?, ?)`, id, until.Unix())
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// Options configure Handler.
type Options struct {
	MaxBody           int64         // default 256 KiB
	RememberFor       time.Duration // default 72 hours
	FailuresPerMinute int           // refusals allowed per minute before 429; default 30
	Log               *slog.Logger  // default slog.Default()
}

// Handler verifies each delivery, then calls next with the raw body. A
// replay of an accepted delivery is answered 200 without calling next, so a
// provider's retry is not processed twice.
func Handler(v Verifier, replay Replay, opts Options, next func(w http.ResponseWriter, r *http.Request, body []byte)) http.Handler {
	if opts.MaxBody == 0 {
		opts.MaxBody = 256 << 10
	}
	if opts.RememberFor == 0 {
		opts.RememberFor = 72 * time.Hour
	}
	if opts.FailuresPerMinute == 0 {
		opts.FailuresPerMinute = 30
	}
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	lim := &limiter{max: opts.FailuresPerMinute}
	refuse := func(w http.ResponseWriter, reason string) {
		opts.Log.Warn("webhook refused", "scheme", v.Name(), "reason", reason)
		if !lim.allow(time.Now()) {
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		http.Error(w, "refused", http.StatusUnauthorized)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, opts.MaxBody))
		if err != nil {
			refuse(w, "body too large or unreadable")
			return
		}
		id, err := v.Verify(r.Header, body, time.Now())
		if err != nil {
			refuse(w, strings.TrimPrefix(err.Error(), "webhook: invalid delivery: "))
			return
		}
		fresh, err := replay.Remember(r.Context(), v.Name()+":"+id, time.Now().Add(opts.RememberFor))
		if err != nil {
			opts.Log.Error("webhook replay store", "err", err)
			http.Error(w, "try again", http.StatusServiceUnavailable)
			return
		}
		if !fresh {
			w.WriteHeader(http.StatusOK)
			return
		}
		next(w, r, body)
	})
}

type limiter struct {
	mu     sync.Mutex
	max    int
	window time.Time
	count  int
}

func (l *limiter) allow(now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Sub(l.window) > time.Minute {
		l.window, l.count = now, 0
	}
	l.count++
	return l.count <= l.max
}
