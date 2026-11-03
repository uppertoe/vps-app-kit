# vps-app-kit

The shared Go module behind every app made from
[vps-app-template](https://github.com/uppertoe/vps-app-template). The kit
holds the parts that must behave identically in every app on the platform: how
an app reads the sign-in gateway's identity, how each route declares who may
reach it, the security headers, SQLite, outbound connections and webhooks.

An app depends on the kit through one line in `go.mod`, and Renovate proposes
each new release. Authors do not edit the kit; a change here reaches every app
at its next update.

## Packages

| Package | What it does |
|---|---|
| `gateway` | Reads `Remote-Email`, `Remote-User` and `Remote-Groups` into an `Identity`. Refuses a repeated or malformed header. The dev stand-in exists only in binaries built with `-tags dev`. |
| `access` | The seven access levels a route can have, each matching one Caddy guard. |
| `router` | Registers routes with their levels, enforces each level in the app as well as in Caddy, deletes identity headers on public and webhook routes, and generates the app's `.caddy` snippet from the route list. |
| `secure` | Content Security Policy with a per-response nonce and no `unsafe-eval` or `unsafe-inline`, the other security headers, the same-origin check on writes, body limits and `no-store` on signed-in pages. |
| `assets` | Content-hashed static URLs (`{{asset "app.css"}}`) served with a year's cache, and `no-cache` for any other URL. |
| `serve` | JSON logs to stdout, a request log with no personal data, graceful shutdown and the `-healthcheck` probe. |
| `sqlitex` | Opens SQLite with WAL and foreign keys, runs numbered migrations and refuses an edited one, checks integrity, and writes the `VACUUM INTO` snapshot the backup copies. |
| `egress` | The only HTTP client an app uses for outside services. Reaches only the hosts in `app.yaml`, over HTTPS on port 443, and never an internal address. |
| `webhook` | Verifies signed deliveries (Standard Webhooks and GitHub), refuses stale and replayed ones, and rate-limits refusals. |
| `mail` | Sends plain-text email through SES over SMTP with STARTTLS, or prints it to the log in development. Refuses line breaks in any header. |
| `manifest` | Reads and validates `app.yaml`, and generates the app's connections page for its design docs. |
| `cmd/kitlint` | The checker the CI workflow runs on an app: no network clients outside the kit, no markup that breaks the CSP, and (`kitlint all`) the rest of the repository. |
| `cmd/kitgate` | Tests the app's access rules through the production Caddy and the published gateway, signing in for real as several kinds of person. |

## Access levels

| Level | Caddy guard | Admits |
|---|---|---|
| `access.Public(reason)` | `strip_public` | Anyone; the app receives no identity |
| `access.Webhook(reason)` | `strip_public` | A delivery with a valid signature; no identity |
| `access.SignedIn()` | `protected` | Any signed-in user except a guest |
| `access.SignedInOrGuest()` | `protected_open` | Any signed-in user and guests from open registration |
| `access.Domain(d...)` | `protected_domains` | Users with an address at one of the domains |
| `access.Group(g...)` | `protected_groups` | Members of one of the groups, including a guest placed in the group and a break-glass card for it |
| `access.DomainOrGroup(d, g)` | `protected_access` | Either of the two above |

A path has one level whatever the method, because Caddy matches on the path
alone. The router panics at start-up on a route with no level, two levels on
one path, or two routes that Caddy could not tell apart.

## Using it

```go
rt := router.New(router.Options{PublicOrigin: cfg.PublicURL, Deny: pages.Deny})
rt.Handle("GET /static/", access.Public("stylesheets, scripts and images"), static.Handler())
rt.HandleFunc("GET /{$}", access.Public("landing page"), h.home)
rt.HandleFunc("GET /records/", access.SignedIn(), h.records)
rt.HandleFunc("POST /admin/settings", access.Group("app_admin"), h.saveSettings)

snippet, err := rt.Caddy(router.Site{Name: "myapp", Host: m.SiteHost()})
```

The template wires all of this up already. Start there rather than here.

## CI for apps

`.github/workflows/app-ci.yml` is the reusable workflow every app runs. An app
calls it from its own `ci.yml`, pinned to a full commit SHA of this
repository. It runs the checks below.

| Job | Checks | When |
|---|---|---|
| `checks` | Formatting, vet, the tests under the race detector, staticcheck, govulncheck, `kitlint all` and gitleaks | Every push and pull request |
| `container` | Builds the image, confirms it holds no dev stand-in, runs it locked down, probes every gated route with forged headers, then runs `kitgate`: every route must admit exactly the people its level names, and refusals must come from the gateway itself | Every push and pull request |
| `publish` | Pushes the image tagged `main` (which the server pins by digest, and Renovate moves) and `sha-<commit>`, with an SBOM and a signed build provenance attestation | Pushes to the default branch only |

`kitlint all` covers the code and templates, the compose file's §5 block,
`.env.example`, the design-docs contract, the vendored files (downloaded again
and compared with the registry), migrations already on the base branch, the
generated Caddy snippet and connections page, the Dockerfile, the
workflows, and, for an app holding personal or health information, a privacy
page in the design docs and a public `/privacy` route. A health app that has not recorded its safeguards gets a warning
on every run, never a failure.

## Versions

The kit follows semantic versioning. Patch releases fix bugs and merge
automatically in apps. Minor and major releases are merged by a person. A
release that changes a security default says so in its notes, under the
heading "Security defaults".

Report a vulnerability privately, as [SECURITY.md](SECURITY.md) describes.
