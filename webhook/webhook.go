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

// MinRememberFor: GitHub signs no timestamp, so a captured delivery stays
// valid for ever; its ID is remembered for 90 days.
func (GitHub) MinRememberFor() time.Duration { return 90 * 24 * time.Hour }

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

// Claim is the outcome of claiming a delivery for processing.
type Claim int

const (
	// Claimed: no one has processed this delivery; process it now.
	Claimed Claim = iota
	// Done: the delivery was processed successfully before; acknowledge it
	// without processing it again.
	Done
	// Busy: another request is processing the same delivery right now; ask
	// the sender to try again later.
	Busy
)

// Replay tracks each delivery through its life. A delivery is marked done
// only after the handler has succeeded, so a delivery whose processing
// failed stays retryable, and the sender's retry is processed afresh.
type Replay interface {
	// Claim takes a delivery for processing, for at most lease. A claim
	// whose lease has run out (the process died mid-way) can be taken again.
	Claim(ctx context.Context, id string, lease time.Duration) (Claim, error)
	// Complete marks a claimed delivery as done, remembered until until.
	Complete(ctx context.Context, id string, until time.Time) error
	// Release gives a claimed delivery back after a failure, so a retry is
	// processed.
	Release(ctx context.Context, id string) error
}

// SQLiteReplay keeps delivery IDs in the app's database.
type SQLiteReplay struct{ db *sql.DB }

// NewSQLiteReplay creates its table if needed.
func NewSQLiteReplay(ctx context.Context, db *sql.DB) (*SQLiteReplay, error) {
	_, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS kit_webhook_deliveries (
		id TEXT PRIMARY KEY,
		state TEXT NOT NULL CHECK (state IN ('processing', 'done')),
		expires INTEGER NOT NULL)`)
	if err == nil {
		// The table of releases before v0.5.0, which recorded a delivery
		// before processing it.
		_, err = db.ExecContext(ctx, `DROP TABLE IF EXISTS kit_webhook_seen`)
	}
	return &SQLiteReplay{db: db}, err
}

func (s *SQLiteReplay) Claim(ctx context.Context, id string, lease time.Duration) (Claim, error) {
	now := time.Now()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM kit_webhook_deliveries WHERE expires < ?`, now.Unix()); err != nil {
		return 0, err
	}
	var state string
	err = tx.QueryRowContext(ctx, `SELECT state FROM kit_webhook_deliveries WHERE id = ?`, id).Scan(&state)
	switch {
	case err == nil && state == "done":
		return Done, tx.Commit()
	case err == nil:
		return Busy, tx.Commit()
	case !errors.Is(err, sql.ErrNoRows):
		return 0, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO kit_webhook_deliveries(id, state, expires) VALUES (?, 'processing', ?)`,
		id, now.Add(lease).Unix()); err != nil {
		return 0, err
	}
	return Claimed, tx.Commit()
}

func (s *SQLiteReplay) Complete(ctx context.Context, id string, until time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE kit_webhook_deliveries SET state = 'done', expires = ? WHERE id = ?`, until.Unix(), id)
	return err
}

func (s *SQLiteReplay) Release(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM kit_webhook_deliveries WHERE id = ? AND state = 'processing'`, id)
	return err
}

// Options configure Handler.
type Options struct {
	MaxBody           int64         // default 256 KiB
	RememberFor       time.Duration // how long a done delivery is remembered; default 72 hours
	Lease             time.Duration // how long a claim lasts if processing never finishes; default 5 minutes
	FailuresPerMinute int           // refusals allowed per minute before 429; default 30
	Log               *slog.Logger  // default slog.Default()
}

// Handler verifies each delivery, claims it, then calls next with the raw
// body. The delivery is marked done only if next answers 2xx; any other
// answer, or a panic, gives it back, so the sender's retry is processed. A
// replay of a done delivery is answered 200 without calling next, and a
// delivery already being processed is answered 503, so the sender retries.
//
// When next changes the database, prefer to make the change idempotent, or
// to record the delivery ID in the same transaction as the change, so that
// a crash between the change and the completion does no harm on retry.
func Handler(v Verifier, replay Replay, opts Options, next func(w http.ResponseWriter, r *http.Request, body []byte)) *Endpoint {
	if opts.MaxBody == 0 {
		opts.MaxBody = 256 << 10
	}
	if opts.RememberFor == 0 {
		opts.RememberFor = 72 * time.Hour
	}
	// A scheme that signs no timestamp (GitHub) relies on the delivery ID
	// alone, so its deliveries are remembered for longer.
	if m, ok := v.(interface{ MinRememberFor() time.Duration }); ok && opts.RememberFor < m.MinRememberFor() {
		opts.RememberFor = m.MinRememberFor()
	}
	if opts.Lease == 0 {
		opts.Lease = 5 * time.Minute
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
	return &Endpoint{h: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		key := v.Name() + ":" + id
		claim, err := replay.Claim(r.Context(), key, opts.Lease)
		if err != nil {
			opts.Log.Error("webhook replay store", "err", err)
			http.Error(w, "try again", http.StatusServiceUnavailable)
			return
		}
		switch claim {
		case Done:
			w.WriteHeader(http.StatusOK)
			return
		case Busy:
			w.Header().Set("Retry-After", "60")
			http.Error(w, "already being processed", http.StatusServiceUnavailable)
			return
		}
		sw := &statusRecorder{ResponseWriter: w}
		returned := false
		// Release on any exit but success, including a panic in next. The
		// store is updated with a fresh context: the request's may be done.
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if returned && sw.ok() {
				if err := replay.Complete(ctx, key, time.Now().Add(opts.RememberFor)); err != nil {
					opts.Log.Error("webhook replay store: complete", "err", err)
				}
				return
			}
			if err := replay.Release(ctx, key); err != nil {
				opts.Log.Error("webhook replay store: release", "err", err)
			}
		}()
		next(sw, r, body)
		returned = true
	})}
}

// Endpoint is a webhook handler that verifies every delivery. The router
// registers a webhook route only with an Endpoint, so an unverified webhook
// cannot be served by mistake. A nil *Endpoint (one not built, as while
// make generate lists the routes) answers 404.
type Endpoint struct{ h http.Handler }

// ServeHTTP verifies and handles a delivery.
func (e *Endpoint) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if e == nil || e.h == nil {
		http.NotFound(w, r)
		return
	}
	e.h.ServeHTTP(w, r)
}

// VerifiesSignatures marks the handler for the router.
func (*Endpoint) VerifiesSignatures() {}

// statusRecorder notes the status next answered with.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	if s.status == 0 {
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	return s.ResponseWriter.Write(b)
}

func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// ok reports a 2xx answer. A handler that wrote nothing has answered 200.
func (s *statusRecorder) ok() bool {
	return s.status == 0 || (s.status >= 200 && s.status < 300)
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
