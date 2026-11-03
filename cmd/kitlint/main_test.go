package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBadFixturesAllFlagged(t *testing.T) {
	fs, err := lint("testdata/bad")
	if err != nil {
		t.Fatal(err)
	}
	count := map[string]int{}
	for _, f := range fs {
		count[f.rule]++
	}
	want := map[string]int{"egress": 6, "exec": 1, "csp": 6, "htmx": 1, "alpine": 1, "escaping": 2}
	for rule, n := range want {
		if count[rule] != n {
			t.Errorf("rule %s: %d findings, want %d (all: %v)", rule, count[rule], n, fs)
		}
	}
}

func TestGoodFixturesClean(t *testing.T) {
	fs, err := lint("testdata/good")
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 0 {
		t.Fatalf("false positives: %v", fs)
	}
}

func TestTestFilesAreExempt(t *testing.T) {
	dir := t.TempDir()
	src := "package x\n\nimport \"net/http\"\n\nvar c = &http.Client{}\n"
	if err := os.WriteFile(filepath.Join(dir, "x_test.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	fs, err := lint(dir)
	if err != nil || len(fs) != 0 {
		t.Fatalf("a test file was flagged: %v %v", fs, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "x.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	if fs, _ := lint(dir); len(fs) != 1 {
		t.Fatalf("the same code outside a test was not flagged: %v", fs)
	}
}
