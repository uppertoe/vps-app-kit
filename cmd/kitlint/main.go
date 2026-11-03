// Command kitlint checks an app made from vps-app-template for the mistakes
// the kit cannot prevent by construction. The reusable CI workflow runs it;
// run it locally with `go run github.com/uppertoe/vps-app-kit/cmd/kitlint .`.
//
// Go code outside the kit must not make its own network clients: no
// http.Get or its siblings, no http.DefaultClient or DefaultTransport, no
// http.Client or http.Transport literals, no net.Dial or tls.Dial, and no
// os/exec. Outside services are reached through egress.New, so app.yaml
// stays the complete list.
//
// Templates must work under the kit's CSP and htmx settings: no inline event
// handlers, no style attributes, no <style> blocks, no hx-on or x-html, and
// no <script> without the nonce.
//
// "kitlint all" adds the checks on the rest of the repository; see all.go.
package main

import (
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

type finding struct {
	pos  string
	rule string
	msg  string
}

// Usage:
//
//	kitlint [dir]                    the code and template checks (as before)
//	kitlint all [-base REF] [-upstream] [dir]
//	                                 every check: code, compose, docs, vendor,
//	                                 migrations, generated files, Dockerfile,
//	                                 workflows and the manifest
func main() {
	args := os.Args[1:]
	var (
		findings []finding
		warnings []finding
		err      error
	)
	if len(args) > 0 && args[0] == "all" {
		fl := flag.NewFlagSet("all", flag.ExitOnError)
		base := fl.String("base", "", "git ref the migrations are compared with, such as origin/main")
		upstream := fl.Bool("upstream", false, "download each vendored file again and compare it with the registry")
		_ = fl.Parse(args[1:])
		root := "."
		if fl.NArg() > 0 {
			root = fl.Arg(0)
		}
		findings, warnings, err = lintAll(root, options{base: *base, upstream: *upstream})
	} else {
		root := "."
		if len(args) > 0 {
			root = args[0]
		}
		findings, err = lint(root)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "kitlint:", err)
		os.Exit(2)
	}
	report("warning", warnings)
	report("error", findings)
	if len(findings) > 0 {
		fmt.Fprintf(os.Stderr, "kitlint: %d finding(s)\n", len(findings))
		os.Exit(1)
	}
}

func report(level string, fs []finding) {
	for _, f := range fs {
		fmt.Printf("%s: %s: %s: %s\n", f.pos, level, f.rule, f.msg)
		if os.Getenv("GITHUB_ACTIONS") == "true" {
			file, line, _ := strings.Cut(f.pos, ":")
			line, _, _ = strings.Cut(line, ":")
			if line == "" {
				line = "1"
			}
			fmt.Printf("::%s file=%s,line=%s,title=kitlint %s::%s\n", level, file, line, f.rule, f.msg)
		}
	}
}

func lint(root string) ([]finding, error) {
	var out []finding
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "vendor", "node_modules", "testdata":
				if path != root {
					return filepath.SkipDir
				}
			}
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		switch {
		case strings.HasSuffix(path, ".go"):
			fs, err := lintGo(path, rel)
			if err != nil {
				return err
			}
			out = append(out, fs...)
		case strings.HasSuffix(path, ".html") || strings.HasSuffix(path, ".tmpl"):
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			out = append(out, lintTemplate(rel, string(b))...)
		}
		return nil
	})
	return out, err
}

var bannedHTTPFuncs = map[string]bool{"Get": true, "Post": true, "Head": true, "PostForm": true}

func lintGo(path, rel string) ([]finding, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	// Map each import's local name to its path, so an aliased import of
	// net/http is still recognised.
	names := map[string]string{}
	for _, imp := range f.Imports {
		p, _ := strconv.Unquote(imp.Path.Value)
		name := p[strings.LastIndex(p, "/")+1:]
		if imp.Name != nil {
			name = imp.Name.Name
		}
		names[name] = p
	}
	var out []finding
	add := func(n ast.Node, rule, msg string) {
		pos := fset.Position(n.Pos())
		pos.Filename = rel
		out = append(out, finding{pos.String(), rule, msg})
	}
	for _, imp := range f.Imports {
		if p, _ := strconv.Unquote(imp.Path.Value); p == "os/exec" {
			add(imp, "exec", "an app must not run other programs")
		}
	}
	pkgOf := func(e ast.Expr) (string, string, bool) {
		sel, ok := e.(*ast.SelectorExpr)
		if !ok {
			return "", "", false
		}
		id, ok := sel.X.(*ast.Ident)
		if !ok {
			return "", "", false
		}
		p, ok := names[id.Name]
		return p, sel.Sel.Name, ok
	}
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.SelectorExpr:
			p, name, ok := pkgOf(x)
			if !ok {
				return true
			}
			switch {
			case p == "net/http" && bannedHTTPFuncs[name]:
				add(x, "egress", "http."+name+" uses the default client; use the client from egress.New")
			case p == "net/http" && (name == "DefaultClient" || name == "DefaultTransport"):
				add(x, "egress", "http."+name+" bypasses the egress allowlist; use egress.New")
			case p == "net" && strings.HasPrefix(name, "Dial"):
				add(x, "egress", "net."+name+" opens a connection outside the egress client")
			case p == "crypto/tls" && strings.HasPrefix(name, "Dial"):
				add(x, "egress", "tls."+name+" opens a connection outside the egress client")
			}
		case *ast.CompositeLit:
			p, name, ok := pkgOf(x.Type)
			if ok && p == "net/http" && (name == "Client" || name == "Transport") {
				add(x, "egress", "an http."+name+" literal bypasses the egress allowlist; use egress.New")
			}
		}
		return true
	})
	return out, nil
}

var (
	reOnAttr     = regexp.MustCompile(`(?i)<[^>]*\son[a-z]+\s*=`)
	reStyleAttr  = regexp.MustCompile(`(?i)<[^>]*\sstyle\s*=`)
	reStyleTag   = regexp.MustCompile(`(?i)<style[\s>]`)
	reHxOn       = regexp.MustCompile(`(?i)\shx-on[:\-=]`)
	reXHTML      = regexp.MustCompile(`(?i)\sx-html\s*=`)
	reScript     = regexp.MustCompile(`(?i)<script\b[^>]*>`)
	reJSURL      = regexp.MustCompile(`(?i)(href|src|action)\s*=\s*["']?\s*javascript:`)
	reExternal   = regexp.MustCompile(`(?i)<(script|link|img|iframe)\b[^>]*\s(src|href)\s*=\s*["']?(https?:)?//`)
	reHTMLHelper = regexp.MustCompile(`\|\s*safeHTML|template\.HTML\b`)
)

func lintTemplate(rel, s string) []finding {
	var out []finding
	lineOf := func(i int) int { return strings.Count(s[:i], "\n") + 1 }
	check := func(re *regexp.Regexp, rule, msg string) {
		for _, m := range re.FindAllStringIndex(s, -1) {
			out = append(out, finding{fmt.Sprintf("%s:%d", rel, lineOf(m[0])), rule, msg})
		}
	}
	check(reOnAttr, "csp", "inline event handler; bind behaviour in app.js with Alpine.data")
	check(reStyleAttr, "csp", "style attribute; use a class, or set a custom property from app.js")
	check(reStyleTag, "csp", "<style> block; move the rules to app.css")
	check(reHxOn, "htmx", "hx-on runs inline script; use an Alpine component")
	check(reXHTML, "alpine", "x-html inserts unescaped HTML; use x-text")
	check(reJSURL, "csp", "javascript: URL")
	check(reExternal, "csp", "a file from another site; vendor it under static/")
	check(reHTMLHelper, "escaping", "unescaped HTML; let html/template escape the value")
	for _, m := range reScript.FindAllStringIndex(s, -1) {
		tag := s[m[0]:m[1]]
		if !strings.Contains(tag, "src=") && !strings.Contains(tag, "nonce=") {
			out = append(out, finding{fmt.Sprintf("%s:%d", rel, lineOf(m[0])), "csp", "inline <script> without the nonce"})
		}
	}
	return out
}
