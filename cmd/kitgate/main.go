// Command kitgate tests an app's access rules through the real sign-in chain.
//
// Given the app's image, it reads the app's own route list and generated
// Caddy snippet from the image, then starts the production Caddy with the
// gateway's guard snippets, the published gateway image, a feed that puts one
// test user in every group the routes use, and the app. It signs in for real,
// reading each one-time code from the gateway's log, and requests every route
// as each kind of person. Each route must admit exactly the people its access
// level names, and must refuse path variants, forged identity headers and
// cross-site writes.
//
//	kitgate -image app:ci
//
// Needs Docker with Compose v2. Leaves nothing behind unless -keep is given.
package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// The versions under test. Renovate keeps the image digests current; the
// guard snippets come from the gateway's repository at the commit named here.
const (
	defaultGatewayImage = "ghcr.io/uppertoe/vps-scaffold-auth:latest@sha256:d2dd0bea3ad0bbae8243d30ea7fbb85a29aca669f690c9bbb9bad7e4a01d94a7"
	defaultGatewayRef   = "e4390c3f9affd51f1c9a608ea17fb6409c9f6bf2"
	// The scaffold commit whose route renderer must accept the app's snippet,
	// as the server repo's render will. Keep it at vps-base-template's main.
	defaultScaffoldRef = "f7c9dea7dad7b397a7263071754489439efedf90"
	defaultCaddyImage  = "caddy:2.11.8-alpine@sha256:f6228111e5fafa1a5238258d0858e103f10599b8d1659a146e7726681a002bb9"
	domain             = "e2e.test"
	project            = "kitgate"
)

var (
	image        = flag.String("image", "", "the app image to test (required)")
	gatewayImage = flag.String("gateway-image", defaultGatewayImage, "the gateway image")
	gatewayRef   = flag.String("gateway-ref", defaultGatewayRef, "the gateway commit whose deploy/auth.caddy is used")
	caddyImage   = flag.String("caddy-image", defaultCaddyImage, "the Caddy image")
	scaffoldRef  = flag.String("scaffold-ref", defaultScaffoldRef, "the vps-base-template commit whose route renderer is used")
	port         = flag.Int("port", 18443, "local port for Caddy")
	keep         = flag.Bool("keep", false, "leave the stack running")
)

func main() {
	flag.Parse()
	if *image == "" {
		fmt.Fprintln(os.Stderr, "kitgate: -image is required")
		os.Exit(2)
	}
	t := &tester{}
	err := t.run()
	if err != nil {
		fmt.Fprintln(os.Stderr, "kitgate:", err)
	}
	if len(t.failures) > 0 || err != nil {
		if t.dir != "" {
			t.printLogs()
		}
	}
	if t.dir != "" && !*keep {
		_ = t.compose("down", "-v", "--remove-orphans")
		os.RemoveAll(t.dir)
	}
	fmt.Printf("\n%d checks, %d failed\n", t.checks, len(t.failures))
	for _, f := range t.failures {
		fmt.Println("FAIL", f)
	}
	if len(t.failures) > 0 || err != nil {
		os.Exit(1)
	}
}

// --- the app's declared routes ---------------------------------------------

type route struct {
	method, path, level string
}

type level struct {
	kind    string // public webhook signedin open domain group either
	domains []string
	groups  []string
}

func parseLevel(s string) level {
	switch {
	case strings.HasPrefix(s, "public"):
		return level{kind: "public"}
	case strings.HasPrefix(s, "webhook"):
		return level{kind: "webhook"}
	case s == "signed in":
		return level{kind: "signedin"}
	case s == "signed in or guest":
		return level{kind: "open"}
	case strings.HasPrefix(s, "domain ") && strings.Contains(s, " or group "):
		d, g, _ := strings.Cut(strings.TrimPrefix(s, "domain "), " or group ")
		return level{kind: "either", domains: strings.Fields(d), groups: strings.Fields(g)}
	case strings.HasPrefix(s, "domain "):
		return level{kind: "domain", domains: strings.Fields(strings.TrimPrefix(s, "domain "))}
	case strings.HasPrefix(s, "group "):
		return level{kind: "group", groups: strings.Fields(strings.TrimPrefix(s, "group "))}
	}
	return level{kind: "unknown"}
}

func parseRoutes(table string) []route {
	var out []route
	for _, line := range strings.Split(table, "\n") {
		f := strings.Fields(line)
		if len(f) < 3 {
			continue
		}
		out = append(out, route{method: f[0], path: f[1], level: strings.Join(f[2:], " ")})
	}
	return out
}

// concrete turns a ServeMux pattern into a path that matches it.
func concrete(p string) string {
	p = strings.ReplaceAll(p, "{$}", "")
	return regexp.MustCompile(`\{[^}]+\}`).ReplaceAllString(p, "x")
}

// --- people -----------------------------------------------------------------

type person struct {
	name   string
	email  string
	role   string // admin, user, guest, or "" for anonymous
	groups []string
	b      *browser
}

func (p *person) admitted(l level) bool {
	if p.role == "" {
		return l.kind == "public" || l.kind == "webhook"
	}
	at := p.email[strings.LastIndex(p.email, "@")+1:]
	inDomain := func() bool {
		for _, d := range l.domains {
			if d == at {
				return p.role != "guest"
			}
		}
		return false
	}
	inGroup := func() bool {
		for _, g := range l.groups {
			if g == "admin" && p.role == "admin" {
				return true
			}
			for _, mine := range p.groups {
				if g == mine {
					return true
				}
			}
		}
		return false
	}
	switch l.kind {
	case "public", "webhook":
		return true
	case "signedin":
		return p.role == "admin" || p.role == "user"
	case "open":
		return true
	case "domain":
		return inDomain()
	case "group":
		return inGroup()
	case "either":
		return inDomain() || inGroup()
	}
	return false
}

// --- the stack --------------------------------------------------------------

type tester struct {
	service      string
	memberGroups []string
	dir          string
	appHost      string
	routes       []route
	people       []*person
	started      time.Time
	checks       int
	failures     []string
}

func (t *tester) failf(format string, a ...any) {
	t.failures = append(t.failures, fmt.Sprintf(format, a...))
}

func (t *tester) check(ok bool, format string, a ...any) {
	t.checks++
	if !ok {
		t.failf(format, a...)
	}
}

func (t *tester) compose(args ...string) error {
	cmd := exec.Command("docker", append([]string{"compose", "-p", project, "-f", filepath.Join(t.dir, "compose.yml")}, args...)...)
	cmd.Dir = t.dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("docker compose %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return nil
}

func (t *tester) logs(service string) string {
	out, _ := exec.Command("docker", "compose", "-p", project, "-f", filepath.Join(t.dir, "compose.yml"),
		"logs", "--no-log-prefix", "--no-color", service).CombinedOutput()
	return string(out)
}

func (t *tester) printLogs() {
	for _, s := range []string{"auth", "caddy", "app", "feed"} {
		lines := strings.Split(strings.TrimSpace(t.logs(s)), "\n")
		if len(lines) > 40 {
			lines = lines[len(lines)-40:]
		}
		fmt.Printf("\n--- %s log (last %d lines) ---\n%s\n", s, len(lines), strings.Join(lines, "\n"))
	}
}

func dockerRun(args ...string) (string, error) {
	out, err := exec.Command("docker", append([]string{"run", "--rm"}, args...)...).Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return "", fmt.Errorf("%v: %s", err, ee.Stderr)
		}
	}
	return string(out), err
}

var (
	membersRe  = regexp.MustCompile(`(?m)^# scaffold-members: ([a-z0-9_ -]+?) --`)
	siteRe     = regexp.MustCompile(`(?m)^([a-z0-9-]+)\.\{\$DOMAIN\} \{$`)
	upstreamRe = regexp.MustCompile(`(?m)(?:reverse_proxy|import protected\S*)(?: "[^"]*")* ([a-z0-9-]+):(\d+)\b`)
)

func (t *tester) run() error {
	table, err := dockerRun(*image, "-routes")
	if err != nil {
		return fmt.Errorf("listing the app's routes: %w", err)
	}
	snippet, err := dockerRun(*image, "-caddy")
	if err != nil {
		return fmt.Errorf("generating the app's Caddy snippet: %w", err)
	}
	t.routes = parseRoutes(table)
	site := siteRe.FindStringSubmatch(snippet)
	up := upstreamRe.FindStringSubmatch(snippet)
	if site == nil || up == nil {
		return errors.New("could not read the site address or upstream from the app's snippet")
	}
	t.appHost = site[1] + "." + domain
	service := up[1]
	t.service = service
	if mm := membersRe.FindStringSubmatch(snippet); mm != nil {
		t.memberGroups = strings.Fields(mm[1])
	}

	// Who to test as, from what the routes use.
	domains, groups := map[string]bool{}, map[string]bool{}
	hasOpen := false
	for _, r := range t.routes {
		l := parseLevel(r.level)
		for _, d := range l.domains {
			domains[d] = true
		}
		for _, g := range l.groups {
			if g != "admin" {
				groups[g] = true
			}
		}
		hasOpen = hasOpen || l.kind == "open"
	}
	for _, g := range t.memberGroups {
		groups[g] = true
	}
	staffDomain := "example.org"
	if len(domains) > 0 {
		staffDomain = sorted(domains)[0]
	}
	allowed := map[string]bool{"example.org": true, "example.net": true}
	for d := range domains {
		allowed[d] = true
	}
	t.people = []*person{
		{name: "anonymous"},
		{name: "staff at " + staffDomain, email: "staff@" + staffDomain, role: "user"},
		{name: "user at another domain", email: "visitor@example.net", role: "user"},
		{name: "member of every group", email: "member@example.net", role: "user", groups: sorted(groups)},
		{name: "gateway admin", email: "boss@example.net", role: "admin"},
	}
	if hasOpen {
		t.people = append(t.people, &person{name: "guest", email: "stranger@guests.example", role: "guest"})
	}

	t.checkRender(snippet, service)

	if err := t.writeStack(snippet, service, sorted(allowed), sorted(groups), hasOpen); err != nil {
		return err
	}
	fmt.Println("kitgate: starting Caddy, the gateway, the feed and", *image)
	if err := t.compose("up", "-d", "--wait", "--wait-timeout", "120"); err != nil {
		return err
	}
	t.started = time.Now()

	t.testAnonymous()
	if len(groups) > 0 || len(t.memberGroups) > 0 {
		// The gateway fills groups from their feeds a minute after it starts,
		// and a person's groups are read when they sign in.
		if wait := 70*time.Second - time.Since(t.started); wait > 0 {
			fmt.Printf("kitgate: waiting %s for the gateway's first group sync\n", wait.Round(time.Second))
			time.Sleep(wait)
		}
	}
	for _, p := range t.people[1:] {
		t.testPerson(p)
	}
	t.testMembers()
	return nil
}

// testMembers reads each group the app declares through the app's own
// -members flag, inside its container, as the app itself would: through the
// gateway's members endpoint with the app's token. A group the app has not
// declared must be refused.
func (t *tester) testMembers() {
	if len(t.memberGroups) == 0 {
		return
	}
	fmt.Println("kitgate: reading group members through the gateway's members endpoint")
	read := func(group string) (string, error) {
		cmd := exec.Command("docker", "compose", "-p", project, "-f", filepath.Join(t.dir, "compose.yml"),
			"exec", "-T", t.service, "/app", "-members", group)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	for _, g := range t.memberGroups {
		out, err := read(g)
		t.check(err == nil && strings.Contains(out, "member@example.net"),
			"reading the members of %s from inside the app: %v\n%s", g, err, out)
	}
	out, err := read("kitgate_undeclared")
	t.check(err != nil && strings.Contains(out, "may not read"),
		"reading a group the app has not declared must be refused, got: %v\n%s", err, out)
}

// checkRender runs the server's route renderer over the app's snippet, as
// the server repo will when the app is added, with the gateway's guard
// snippets beside it. A snippet the renderer refuses could not be deployed.
func (t *tester) checkRender(snippet, service string) {
	fmt.Println("kitgate: rendering the snippet with the scaffold's route renderer")
	dir, err := os.MkdirTemp("", "kitgate-render-")
	if err != nil {
		t.failf("render check: %v", err)
		return
	}
	defer os.RemoveAll(dir)
	renderer, err := fetch("https://raw.githubusercontent.com/uppertoe/vps-base-template/" + *scaffoldRef + "/docker/render-caddy-routes.sh")
	if err != nil {
		t.failf("render check: fetching the renderer: %v", err)
		return
	}
	// The auth app is present, as on a server, so an app that reads group
	// members can be rendered; its own snippet is not under test here.
	authCaddy := "# scaffold-lint: public -- the sign-in service\nauth.{$DOMAIN} {\n\treverse_proxy auth:8080 {\n\t\timport strip_public\n\t}\n}\n"
	files := map[string]string{
		"render.sh":                                  renderer,
		"docker-compose.yml":                         "include:\n  - apps/auth/docker-compose.yml\n  - apps/" + service + "/docker-compose.yml\n",
		"apps/auth/docker-compose.yml":               "services:\n  auth:\n    image: example/auth\n",
		"apps/auth/auth.caddy":                       authCaddy,
		"apps/" + service + "/docker-compose.yml":    "services:\n  " + service + ":\n    image: example/app\n",
		"apps/" + service + "/" + service + ".caddy": snippet,
	}
	for name, body := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.failf("render check: %v", err)
			return
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.failf("render check: %v", err)
			return
		}
	}
	out, err := exec.Command("bash", filepath.Join(dir, "render.sh"), dir, filepath.Join(dir, "out")).CombinedOutput()
	t.check(err == nil, "the server's route renderer refuses the app's snippet:\n%s", out)
}

func sorted(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (t *tester) writeStack(snippet, service string, allowed, groups []string, hasOpen bool) error {
	dir, err := os.MkdirTemp("", "kitgate-")
	if err != nil {
		return err
	}
	t.dir = dir
	authCaddy, err := fetch("https://raw.githubusercontent.com/uppertoe/vps-scaffold-auth/" + *gatewayRef + "/deploy/auth.caddy")
	if err != nil {
		return fmt.Errorf("fetching the gateway's guard snippets: %w", err)
	}
	feedToken := randHex(16)
	var feedRoutes, feeds, feedEnv strings.Builder
	for _, g := range groups {
		fmt.Fprintf(&feedRoutes, "\thandle /%s {\n\t\t@ok header Authorization \"Bearer %s\"\n\t\thandle @ok {\n\t\t\theader Content-Type application/json\n\t\t\trespond `[\"member@example.net\"]` 200\n\t\t}\n\t\trespond 401\n\t}\n", g, feedToken)
		fmt.Fprintf(&feeds, "%s=http://feed/%s ", g, g)
		fmt.Fprintf(&feedEnv, "      - GROUP_FEED_TOKEN_%s=%s\n", strings.ToUpper(strings.NewReplacer("-", "_").Replace(g)), feedToken)
	}
	openHosts := ""
	if hasOpen {
		openHosts = t.appHost
	}
	// The app's token for the gateway's members endpoint, when it reads any.
	var readers, appMembers string
	if len(t.memberGroups) > 0 {
		readerToken := randHex(32)
		envName := strings.ToUpper(strings.NewReplacer("-", "_").Replace(service))
		readers = fmt.Sprintf("      - MEMBER_READERS=%s=%s\n      - MEMBER_READER_TOKEN_%s=%s\n",
			service, strings.Join(t.memberGroups, ","), envName, readerToken)
		appMembers = "      - GATEWAY_MEMBERS_URL=http://auth:8081\n      - GATEWAY_MEMBERS_TOKEN=" + readerToken + "\n"
	}
	files := map[string]string{
		"auth.caddy": authCaddy,
		"app.caddy":  snippet,
		"Caddyfile": "{\n\tadmin off\n\tlocal_certs\n\tskip_install_trust\n\tauto_https disable_redirects\n}\n\n" +
			"import /etc/caddy/auth.caddy\nimport /etc/caddy/app.caddy\n",
		"feed.Caddyfile": ":80 {\n" + feedRoutes.String() + "\trespond 404\n}\n",
		"compose.yml": fmt.Sprintf(`services:
  caddy:
    image: %[1]s
    environment:
      - DOMAIN=%[2]s
    ports:
      - "127.0.0.1:%[3]d:443"
    volumes:
      - ./Caddyfile:/etc/caddy/Caddyfile:ro
      - ./auth.caddy:/etc/caddy/auth.caddy:ro
      - ./app.caddy:/etc/caddy/app.caddy:ro
    depends_on:
      auth:
        condition: service_healthy
      %[4]s:
        condition: service_healthy
  auth:
    image: %[5]s
    user: "65532:65532"
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    read_only: true
    tmpfs: [/tmp]
    volumes:
      - auth_data:/data
    environment:
      - DOMAIN=%[2]s
      - AUTH_PUBLIC_URL=https://auth.%[2]s
      - ALLOWED_EMAIL_DOMAINS=%[6]s
      - ADMIN_EMAILS=boss@example.net
      - OPEN_REGISTRATION_HOSTS=%[7]s
      - SESSION_SECRET=%[8]s
      - DATA_ENCRYPTION_KEY=%[9]s
      - EMAIL_BACKEND=log
      - EMAIL_FROM=Sign-in <auth@%[2]s>
      - COOKIE_INSECURE=true
      - TOTP_ENABLED=false
      - OTP_LENGTH=8
      - RATELIMIT_PER_IP=200/15m
      - GROUP_FEEDS=%[10]s
%[11]s%[14]s    healthcheck:
      test: ["CMD", "/app", "-healthcheck"]
      interval: 2s
      timeout: 2s
      retries: 30
  feed:
    image: %[1]s
    volumes:
      - ./feed.Caddyfile:/etc/caddy/Caddyfile:ro
  %[4]s:
    image: %[12]s
    user: "65532:65532"
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    read_only: true
    tmpfs: [/tmp]
    volumes:
      - app_data:/data
    environment:
      - PUBLIC_URL=https://%[13]s
%[15]s    healthcheck:
      test: ["CMD", "/app", "-healthcheck"]
      interval: 2s
      timeout: 2s
      retries: 30
volumes:
  auth_data:
  app_data:
`, *caddyImage, domain, *port, service, *gatewayImage, strings.Join(allowed, ","), openHosts,
			randHex(32), randHex(32), strings.TrimSpace(feeds.String()), feedEnv.String(), *image, t.appHost,
			readers, appMembers),
	}
	if len(groups) == 0 {
		files["compose.yml"] = strings.Replace(files["compose.yml"], "      - GROUP_FEEDS=\n", "", 1)
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			return err
		}
	}
	return nil
}

func fetch(u string) (string, error) {
	c := &http.Client{Timeout: 30 * time.Second}
	resp, err := c.Get(u)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("%s: status %d", u, resp.StatusCode)
	}
	b, err := io.ReadAll(resp.Body)
	return string(b), err
}

// --- a browser --------------------------------------------------------------

type browser struct {
	c   *http.Client
	jar *cookiejar.Jar
}

type reply struct {
	status   int
	location string
	body     string
}

func newBrowser() *browser {
	jar, _ := cookiejar.New(nil)
	d := &net.Dialer{Timeout: 5 * time.Second}
	addr := fmt.Sprintf("127.0.0.1:%d", *port)
	return &browser{jar: jar, c: &http.Client{
		Jar:     jar,
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return d.DialContext(ctx, network, addr)
			},
			// Caddy's local CA for the throwaway test domain.
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

func (b *browser) do(method, target, rawPath string, form url.Values, hdr map[string]string) (reply, error) {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequest(method, target, body)
	if err != nil {
		return reply{}, err
	}
	if rawPath != "" {
		req.URL.RawPath = rawPath
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range hdr {
		req.Header.Add(k, v)
	}
	res, err := b.c.Do(req)
	if err != nil {
		return reply{}, err
	}
	defer res.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	return reply{status: res.StatusCode, location: res.Header.Get("Location"), body: string(data)}, nil
}

var reHidden = regexp.MustCompile(`<input type="hidden" name="([^"]+)" value="([^"]*)">`)

func hidden(page string) url.Values {
	v := url.Values{}
	for _, m := range reHidden.FindAllStringSubmatch(page, -1) {
		v.Set(m[1], html.UnescapeString(m[2]))
	}
	return v
}

// --- sign-in ----------------------------------------------------------------

func (t *tester) codeFor(email string, after int) (string, error) {
	re := regexp.MustCompile(`to=` + regexp.QuoteMeta(email) + ` subject="(\d+) is your sign-in code"`)
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if all := re.FindAllStringSubmatch(t.logs("auth"), -1); len(all) > after {
			return all[len(all)-1][1], nil
		}
		time.Sleep(300 * time.Millisecond)
	}
	return "", fmt.Errorf("no sign-in code was mailed to %s", email)
}

func (t *tester) signIn(p *person, start string) error {
	auth := "https://auth." + domain
	r, err := p.b.do("GET", "https://"+t.appHost+start, "", nil, nil)
	if err != nil {
		return err
	}
	if r.status != http.StatusFound || !strings.HasPrefix(r.location, auth+"/login") {
		return fmt.Errorf("GET %s without a session answered %d to %q, not the sign-in page", start, r.status, r.location)
	}
	login, err := p.b.do("GET", r.location, "", nil, nil)
	if err != nil {
		return err
	}
	before := len(regexp.MustCompile(`to=`+regexp.QuoteMeta(p.email)+` subject=`).FindAllString(t.logs("auth"), -1))
	nav := map[string]string{"Origin": "null", "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "navigate"}
	form := hidden(login.body)
	form.Set("email", p.email)
	codePage, err := p.b.do("POST", auth+"/request", "", form, nav)
	if err != nil {
		return err
	}
	if codePage.status != http.StatusOK {
		return fmt.Errorf("requesting a code for %s answered %d", p.email, codePage.status)
	}
	code, err := t.codeFor(p.email, before)
	if err != nil {
		return err
	}
	form = hidden(codePage.body)
	form.Set("code", code)
	done, err := p.b.do("POST", auth+"/verify-code", "", form, nav)
	if err != nil {
		return err
	}
	if done.status != http.StatusFound {
		return fmt.Errorf("entering the code for %s answered %d", p.email, done.status)
	}
	return nil
}

// --- the checks ---------------------------------------------------------------

// outcome reads a reply as admitted (the app answered) or refused (the
// gateway redirected to sign in or to its refusal page, or someone answered
// 401 or 403).
func admittedBy(r reply) bool {
	if (r.status == http.StatusFound || r.status == http.StatusSeeOther || r.status == http.StatusTemporaryRedirect) &&
		strings.HasPrefix(r.location, "https://auth."+domain) {
		return false
	}
	return r.status != http.StatusUnauthorized && r.status != http.StatusForbidden
}

// gatewayRefused reads a reply as refused by the gateway itself: a redirect
// to sign in or to its refusal page. The app refuses as well (either layer
// alone holds), but a refusal must come from the gateway, or Caddy's guard is
// weaker than the route declares.
func gatewayRefused(r reply) bool {
	return (r.status == http.StatusFound || r.status == http.StatusSeeOther || r.status == http.StatusTemporaryRedirect) &&
		strings.HasPrefix(r.location, "https://auth."+domain)
}

// matches reports whether a reply is what the route's level says for this
// person: the app answered, or the gateway refused.
func matches(r reply, want bool) bool {
	if want {
		return admittedBy(r)
	}
	return gatewayRefused(r)
}

func describe(r reply) string {
	if r.location != "" {
		return fmt.Sprintf("%d to %s", r.status, r.location)
	}
	return fmt.Sprint(r.status)
}

func (t *tester) request(p *person, rt route, path string, extra map[string]string) (reply, error) {
	target := "https://" + t.appHost + path
	switch rt.method {
	case "GET", "HEAD", "*":
		return p.b.do("GET", target, "", nil, extra)
	default:
		h := map[string]string{"Origin": "https://" + t.appHost, "Sec-Fetch-Site": "same-origin"}
		for k, v := range extra {
			h[k] = v
		}
		return p.b.do(rt.method, target, "", url.Values{}, h)
	}
}

func (t *tester) testAnonymous() {
	anon := t.people[0]
	anon.b = newBrowser()
	fmt.Println("kitgate: testing as anonymous")
	for _, rt := range t.routes {
		l := parseLevel(rt.level)
		path := concrete(rt.path)
		r, err := t.request(anon, rt, path, nil)
		if err != nil {
			t.failf("%s %s as anonymous: %v", rt.method, path, err)
			continue
		}
		t.check(matches(r, anon.admitted(l)), "%s %s (%s) as anonymous: got %s", rt.method, path, rt.level, describe(r))
		if l.kind == "webhook" {
			t.check(r.status == http.StatusUnauthorized && !strings.HasPrefix(r.location, "https://auth."),
				"%s %s: an unsigned delivery must reach the app and be refused there, got %s", rt.method, path, describe(r))
		}
		if l.kind == "public" || l.kind == "webhook" || rt.method != "GET" {
			continue
		}
		// Forged identity headers never admit anyone.
		forged, err := t.request(anon, rt, path, map[string]string{
			"Remote-Email": "boss@example.net", "Remote-User": "boss@example.net", "Remote-Groups": "admin," + strings.Join(l.groups, ","),
		})
		if err == nil {
			t.check(gatewayRefused(forged), "%s %s with forged identity headers: got %s, want the gateway to refuse", rt.method, path, describe(forged))
		}
		// Other methods on the same path are refused by the gateway too:
		// Caddy guards a path whatever the method.
		for _, m := range []string{"HEAD", "POST", "DELETE"} {
			r, err := anon.b.do(m, "https://"+t.appHost+path, "", nil, map[string]string{"Origin": "https://" + t.appHost})
			if err == nil {
				t.check(gatewayRefused(r), "%s %s (gated) as anonymous: got %s, want the gateway to refuse", m, path, describe(r))
			}
		}
		// Spellings of the same path must not slip past the gate.
		for _, v := range variants(path) {
			r, err := anon.b.do("GET", "https://"+t.appHost+v.path, v.raw, nil, nil)
			if err != nil {
				continue
			}
			t.check(r.status < 200 || r.status >= 300, "GET %s (a variant of gated %s) answered %d to anonymous", v.show(), path, r.status)
		}
	}
	r, err := anon.b.do("GET", "https://"+t.appHost+"/kitgate-unregistered-"+randHex(4), "", nil, nil)
	if err == nil {
		t.check(r.status == http.StatusNotFound, "an unregistered path answered %s, want 404", describe(r))
	}
}

type variant struct{ path, raw string }

func (v variant) show() string {
	if v.raw != "" {
		return v.raw
	}
	return v.path
}

func variants(p string) []variant {
	if p == "/" || len(p) < 2 {
		return nil
	}
	first := p[1:2]
	vs := []variant{
		{path: strings.ToUpper(p)},
		{path: "/" + p},
		{path: "/." + p},
		{path: "/x/.." + p},
		{path: p + "/"},
		{path: p, raw: "/%" + strings.ToUpper(hex.EncodeToString([]byte(first))) + p[2:]},
	}
	// An encoded slash inside a path that has more than one segment.
	if i := strings.Index(p[1:], "/"); i > 0 {
		vs = append(vs, variant{path: p, raw: p[:i+1] + "%2F" + p[i+2:]})
	}
	return vs
}

func (t *tester) testPerson(p *person) {
	p.b = newBrowser()
	// Start the sign-in at a route this person may reach, so a domain gate
	// does not decline them before they sign in.
	start := ""
	for _, rt := range t.routes {
		l := parseLevel(rt.level)
		if rt.method == "GET" && l.kind != "public" && l.kind != "webhook" && p.admitted(l) {
			if p.role == "guest" && l.kind != "open" {
				continue
			}
			start = concrete(rt.path)
			break
		}
	}
	if start == "" {
		fmt.Printf("kitgate: no route admits %s; checking that sign-in alone admits them nowhere\n", p.name)
		for _, rt := range t.routes {
			l := parseLevel(rt.level)
			if rt.method == "GET" && l.kind == "group" {
				start = concrete(rt.path)
				break
			}
		}
		if start == "" {
			return
		}
	}
	fmt.Printf("kitgate: signing in as %s (%s)\n", p.name, p.email)
	if err := t.signIn(p, start); err != nil {
		t.failf("signing in as %s: %v", p.name, err)
		return
	}
	for _, rt := range t.routes {
		l := parseLevel(rt.level)
		if l.kind == "webhook" {
			continue
		}
		path := concrete(rt.path)
		r, err := t.request(p, rt, path, nil)
		if err != nil {
			t.failf("%s %s as %s: %v", rt.method, path, p.name, err)
			continue
		}
		t.check(matches(r, p.admitted(l)), "%s %s (%s) as %s: got %s", rt.method, path, rt.level, p.name, describe(r))

		if rt.method != "GET" && p.admitted(l) {
			// The same write from another site is refused.
			x, err := p.b.do(rt.method, "https://"+t.appHost+path, "", url.Values{},
				map[string]string{"Origin": "https://evil." + domain, "Sec-Fetch-Site": "same-site"})
			if err == nil {
				t.check(x.status == http.StatusForbidden, "%s %s from another site as %s: got %s, want 403", rt.method, path, p.name, describe(x))
			}
		}
		if rt.method == "GET" && !p.admitted(l) && len(l.groups) > 0 {
			// A signed-in person who claims the group in a header is still refused.
			x, err := p.b.do("GET", "https://"+t.appHost+path, "", nil,
				map[string]string{"Remote-Groups": p.role + "," + strings.Join(l.groups, ",")})
			if err == nil {
				t.check(gatewayRefused(x), "GET %s as %s claiming its group in a header: got %s, want the gateway to refuse", path, p.name, describe(x))
			}
		}
	}
}
