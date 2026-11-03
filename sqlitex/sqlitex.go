// Package sqlitex opens an app's SQLite database the way every app on the
// platform should: WAL, foreign keys on every connection, a busy timeout,
// one writer, embedded migrations that cannot be edited once run, and a
// consistent snapshot file for the backup to copy.
//
// The driver is modernc.org/sqlite, which is pure Go, so the binary stays
// static and the image distroless.
package sqlitex

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// Open opens (creating if needed) the database at path. The pool has one
// connection, so writes never contend. With one connection, a query issued
// while a rows cursor is still open waits for ever: read rows into a slice
// before issuing the next query.
func Open(path string) (*sql.DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", dsn(path))
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		db.Close()
		return nil, fmt.Errorf("sqlitex: journal mode: %w", err)
	}
	// The database and its WAL hold the app's records: owner only.
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		_ = os.Chmod(p, 0o600)
	}
	return db, nil
}

func dsn(path string) string {
	return "file:" + path + "?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_txlock=immediate"
}

var migrationName = regexp.MustCompile(`^(\d{4})_[a-z0-9_]+\.sql$`)

// Migrate applies every NNNN_name.sql file in fsys that has not run, in name
// order, each in its own transaction. It records each file's SHA-256 and
// refuses to start if a file that has already run has changed since: a
// schema change is always a new numbered file.
func Migrate(ctx context.Context, db *sql.DB, fsys fs.FS) error {
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS kit_migrations (
		name TEXT PRIMARY KEY, sha256 TEXT NOT NULL, applied_at TEXT NOT NULL)`); err != nil {
		return err
	}
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return err
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if !migrationName.MatchString(e.Name()) {
			return fmt.Errorf("sqlitex: migration %q must be named NNNN_lower_case.sql", e.Name())
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)
	applied := map[string]string{}
	rows, err := db.QueryContext(ctx, `SELECT name, sha256 FROM kit_migrations`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var n, h string
		if err := rows.Scan(&n, &h); err != nil {
			rows.Close()
			return err
		}
		applied[n] = h
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, n := range names {
		b, err := fs.ReadFile(fsys, n)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(b)
		h := hex.EncodeToString(sum[:])
		if prev, ok := applied[n]; ok {
			if prev != h {
				return fmt.Errorf("sqlitex: migration %s has changed since it ran; add a new numbered file instead", n)
			}
			continue
		}
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, string(b)); err != nil {
			tx.Rollback()
			return fmt.Errorf("sqlitex: migration %s: %w", n, err)
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO kit_migrations(name, sha256, applied_at) VALUES (?, ?, ?)`,
			n, h, time.Now().UTC().Format(time.RFC3339)); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// ErrCorrupt is returned by Check when SQLite reports damage.
var ErrCorrupt = errors.New("sqlitex: integrity check failed")

// Check runs PRAGMA quick_check. Run it at start-up and daily; on
// ErrCorrupt, alert and restore from the latest snapshot.
func Check(ctx context.Context, db *sql.DB) error {
	var res string
	if err := db.QueryRowContext(ctx, "PRAGMA quick_check").Scan(&res); err != nil {
		return err
	}
	if res != "ok" {
		return fmt.Errorf("%w: %s", ErrCorrupt, strings.SplitN(res, "\n", 2)[0])
	}
	return nil
}

// Snapshot writes a consistent copy of the database at dbPath to dest with
// VACUUM INTO. restic copying the live file and its WAL at different
// instants can produce a backup that does not restore; the snapshot is
// always a whole database, so the backup points at the snapshot folder.
//
// It runs on its own connection, so the app's single connection stays free
// for requests while the copy is made. It writes beside dest, syncs, sets
// mode 600 and renames over dest, so the previous snapshot survives a
// failure part-way.
func Snapshot(ctx context.Context, dbPath, dest string) error {
	if err := os.MkdirAll(filepath.Dir(dest), 0o700); err != nil {
		return err
	}
	tmp := dest + ".tmp"
	_ = os.Remove(tmp)
	snap, err := sql.Open("sqlite", "file:"+dbPath+"?_pragma=busy_timeout(5000)")
	if err != nil {
		return err
	}
	defer snap.Close()
	snap.SetMaxOpenConns(1)
	if _, err := snap.ExecContext(ctx, `VACUUM INTO ?`, tmp); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Chmod(tmp, 0o600); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	f, err := os.Open(tmp)
	if err != nil {
		return err
	}
	err = f.Sync()
	f.Close()
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, dest); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if d, err := os.Open(filepath.Dir(dest)); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return nil
}

// SnapshotEvery takes a snapshot now and then at each interval until ctx is
// done, reporting failures to onErr.
func SnapshotEvery(ctx context.Context, dbPath, dest string, every time.Duration, onErr func(error)) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if err := Snapshot(ctx, dbPath, dest); err != nil && ctx.Err() == nil {
			onErr(err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
