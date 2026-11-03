package sqlitex

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
)

func TestMigrateAndSnapshot(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "app.db")
	db, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	migs := fstest.MapFS{
		"0001_init.sql":  {Data: []byte("CREATE TABLE people (id INTEGER PRIMARY KEY, name TEXT NOT NULL);")},
		"0002_notes.sql": {Data: []byte("CREATE TABLE notes (id INTEGER PRIMARY KEY, person INTEGER NOT NULL REFERENCES people(id));")},
	}
	if err := Migrate(ctx, db, migs); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, db, migs); err != nil {
		t.Fatalf("second run should be a no-op: %v", err)
	}
	if _, err := db.Exec("INSERT INTO notes(person) VALUES (99)"); err == nil {
		t.Fatal("foreign keys are not enforced")
	}
	if _, err := db.Exec("INSERT INTO people(name) VALUES ('Ann')"); err != nil {
		t.Fatal(err)
	}
	if err := Check(ctx, db); err != nil {
		t.Fatal(err)
	}

	migs["0001_init.sql"] = &fstest.MapFile{Data: []byte("CREATE TABLE people (id INTEGER PRIMARY KEY);")}
	if err := Migrate(ctx, db, migs); err == nil || !strings.Contains(err.Error(), "has changed") {
		t.Fatalf("an edited migration must be refused, got %v", err)
	}

	snap := filepath.Join(dir, "snapshot", "app.db")
	if err := Snapshot(ctx, path, snap); err != nil {
		t.Fatal(err)
	}
	if err := Snapshot(ctx, path, snap); err != nil {
		t.Fatalf("a second snapshot must replace the first: %v", err)
	}
	fi, err := os.Stat(snap)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("snapshot mode %v, want 0600", fi.Mode().Perm())
	}
	copyDB, err := Open(snap)
	if err != nil {
		t.Fatal(err)
	}
	defer copyDB.Close()
	var name string
	if err := copyDB.QueryRow("SELECT name FROM people").Scan(&name); err != nil || name != "Ann" {
		t.Fatalf("snapshot content: %q %v", name, err)
	}
}

func TestMigrationNames(t *testing.T) {
	db, err := Open(filepath.Join(t.TempDir(), "x.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := Migrate(context.Background(), db, fstest.MapFS{"init.sql": {Data: []byte("SELECT 1;")}}); err == nil {
		t.Fatal("an unnumbered migration must be refused")
	}
}
