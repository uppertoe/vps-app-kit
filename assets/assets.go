// Package assets serves an app's static files under content-hashed URLs.
//
// Every URL that URL() returns carries ?v=<hash of all static files>. Such a
// response is cached for a year, because a changed file produces a new URL.
// A request without the current hash is served with no-cache, so a stale or
// hand-typed URL never sticks in a browser. The platform's Caddy serves
// fingerprinted URLs straight through the login check for the same reason.
package assets

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"time"
)

// Placeholder in a .css file is replaced by the version, so a stylesheet can
// point at fonts and images with url("/static/x.woff2?v=__ASSET_V__").
const Placeholder = "__ASSET_V__"

// Set is a tree of static files mounted at a URL prefix.
type Set struct {
	fsys    fs.FS
	prefix  string
	version string
	css     map[string][]byte
}

// New hashes every file in fsys and prepares the set to be served at prefix,
// such as "/static/".
func New(fsys fs.FS, prefix string) (*Set, error) {
	if !strings.HasPrefix(prefix, "/") || !strings.HasSuffix(prefix, "/") {
		prefix = "/" + strings.Trim(prefix, "/") + "/"
	}
	s := &Set{fsys: fsys, prefix: prefix, css: map[string][]byte{}}
	h := sha256.New()
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := fs.ReadFile(fsys, p)
		if err != nil {
			return err
		}
		h.Write([]byte(p))
		h.Write([]byte{0})
		h.Write(b)
		return nil
	})
	if err != nil {
		return nil, err
	}
	s.version = hex.EncodeToString(h.Sum(nil))[:12]
	err = fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || path.Ext(p) != ".css" {
			return err
		}
		b, err := fs.ReadFile(fsys, p)
		if err != nil {
			return err
		}
		s.css[p] = bytes.ReplaceAll(b, []byte(Placeholder), []byte(s.version))
		return nil
	})
	return s, err
}

// Version is the content hash carried on every URL.
func (s *Set) Version() string { return s.version }

// URL returns the cache-busted URL for a file, such as URL("app.css").
// Templates call it as {{asset "app.css"}}.
func (s *Set) URL(name string) string {
	return s.prefix + strings.TrimPrefix(name, "/") + "?v=" + s.version
}

// Handler serves the files. Mount it at the prefix as a public route.
func (s *Set) Handler() http.Handler {
	files := http.FileServerFS(s.fsys)
	return http.StripPrefix(strings.TrimSuffix(s.prefix, "/"), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/") {
			http.NotFound(w, r) // no directory listings
			return
		}
		if r.URL.Query().Get("v") == s.version {
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		} else {
			w.Header().Set("Cache-Control", "no-cache")
		}
		name := strings.TrimPrefix(r.URL.Path, "/")
		if b, ok := s.css[name]; ok {
			w.Header().Set("Content-Type", "text/css; charset=utf-8")
			http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(b))
			return
		}
		files.ServeHTTP(w, r)
	}))
}
