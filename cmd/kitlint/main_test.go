package main

import "testing"

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
