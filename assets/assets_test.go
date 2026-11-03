package assets

import (
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

func TestAssets(t *testing.T) {
	fsys := fstest.MapFS{
		"app.css":        {Data: []byte(`@font-face{src:url("/static/f.woff2?v=__ASSET_V__")}`)},
		"js/app.js":      {Data: []byte("x")},
		"brand/logo.svg": {Data: []byte("<svg/>")},
	}
	s, err := New(fsys, "/static/")
	if err != nil {
		t.Fatal(err)
	}
	u := s.URL("app.css")
	if u != "/static/app.css?v="+s.Version() {
		t.Fatalf("url %s", u)
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest("GET", u, nil))
	if w.Code != 200 || !strings.Contains(w.Header().Get("Cache-Control"), "immutable") {
		t.Fatalf("hashed url: %d %v", w.Code, w.Header())
	}
	if !strings.Contains(w.Body.String(), "?v="+s.Version()) {
		t.Fatalf("placeholder not replaced: %s", w.Body.String())
	}
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/static/js/app.js?v=old", nil))
	if w.Header().Get("Cache-Control") != "no-cache" {
		t.Fatal("a stale hash must not be cached")
	}
	w = httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest("GET", "/static/brand/", nil))
	if w.Code != 404 {
		t.Fatal("directory listing served")
	}

	fsys["js/app.js"] = &fstest.MapFile{Data: []byte("y")}
	s2, _ := New(fsys, "/static/")
	if s2.Version() == s.Version() {
		t.Fatal("a changed file must change the version")
	}
}
