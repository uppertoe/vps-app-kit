package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/mail"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
	"time"
)

// The gateway's members endpoint lets an app ask who is in a group when
// nobody is signed in, as a weekly email to the group needs. Membership
// stays in the gateway: the app reads it at the moment it needs it and keeps
// no copy. The gateway serves it on its internal port (http://auth:8081),
// reachable only over the app's own <app>_members network, which the
// server's route renderer creates for apps whose app.yaml lists members.

// Errors from Members. ErrMembersRefused means the configuration is wrong,
// not that the group is empty: the app may not read that group, or the
// group does not exist yet. Never treat it as "nobody".
var (
	ErrMembersNotConfigured = errors.New("gateway: the members endpoint is not configured (GATEWAY_MEMBERS_URL and GATEWAY_MEMBERS_TOKEN)")
	ErrMembersUnauthorized  = errors.New("gateway: the members endpoint refused the token")
	ErrMembersRefused       = errors.New("gateway: this app may not read that group, or the group does not exist")
	ErrMembersUnavailable   = errors.New("gateway: the members endpoint is unavailable")
)

// MembersClient reads group members from the gateway.
type MembersClient struct {
	base  *url.URL
	token string
	http  *http.Client
	// sleep is replaced in tests.
	sleep func(context.Context, time.Duration) error
}

// NewMembersClient returns a client for the gateway at baseURL, such as
// http://auth:8081, using the app's token. Both come from the app's .env.
// With either empty, it returns a client whose every call returns
// ErrMembersNotConfigured, so an app can start without the feature.
func NewMembersClient(baseURL, token string) (*MembersClient, error) {
	c := &MembersClient{sleep: sleepCtx}
	if baseURL == "" && token == "" {
		return c, nil
	}
	u, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil || u.Scheme != "http" || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" {
		return nil, fmt.Errorf("gateway: GATEWAY_MEMBERS_URL must be the gateway's internal address, such as http://auth:8081")
	}
	if len(token) < 32 {
		return nil, errors.New("gateway: GATEWAY_MEMBERS_TOKEN must be at least 32 characters")
	}
	c.base, c.token = u, token
	dialer := &net.Dialer{Timeout: 5 * time.Second, Control: internalOnly}
	c.http = &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			Proxy:       nil, // the gateway refuses proxied requests
			DialContext: dialer.DialContext,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return c, nil
}

// internalOnly refuses to dial anything but a private or loopback address:
// the members endpoint lives inside the server, never on the internet.
func internalOnly(network, address string, _ syscall.RawConn) error {
	ap, err := netip.ParseAddrPort(address)
	if err != nil {
		return err
	}
	a := ap.Addr().Unmap()
	if !a.IsPrivate() && !a.IsLoopback() {
		return fmt.Errorf("gateway: %s is not an internal address", a)
	}
	return nil
}

// Members returns the addresses of a group's members, sorted, as the gateway
// knows them now. It retries a rate limit or a server error a few times with
// backoff. Read at the time of use; do not cache the answer.
func (c *MembersClient) Members(ctx context.Context, group string) ([]string, error) {
	group = strings.ToLower(strings.TrimSpace(group))
	if group == "" || strings.ContainsAny(group, "/?#% ") {
		return nil, fmt.Errorf("gateway: %q is not a group name", group)
	}
	if c.base == nil {
		return nil, ErrMembersNotConfigured
	}
	wait := time.Second
	var last error
	for attempt := 0; attempt < 4; attempt++ {
		if attempt > 0 {
			if err := c.sleep(ctx, wait); err != nil {
				return nil, err
			}
			wait *= 2
		}
		members, retry, err := c.read(ctx, group)
		if !retry {
			return members, err
		}
		last = err
	}
	return nil, last
}

type membersReply struct {
	Group   string   `json:"group"`
	Members []string `json:"members"`
}

func (c *MembersClient) read(ctx context.Context, group string) (members []string, retry bool, err error) {
	u := c.base.JoinPath("v1", "groups", group, "members")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, ctx.Err() == nil, fmt.Errorf("%w: %v", ErrMembersUnavailable, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, true, fmt.Errorf("%w: %v", ErrMembersUnavailable, err)
	}
	switch {
	case resp.StatusCode == http.StatusOK:
	case resp.StatusCode == http.StatusUnauthorized:
		return nil, false, ErrMembersUnauthorized
	case resp.StatusCode == http.StatusForbidden:
		return nil, false, ErrMembersRefused
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		return nil, true, fmt.Errorf("%w: status %d", ErrMembersUnavailable, resp.StatusCode)
	default:
		return nil, false, fmt.Errorf("%w: status %d", ErrMembersUnavailable, resp.StatusCode)
	}
	var r membersReply
	if err := json.Unmarshal(body, &r); err != nil || r.Members == nil {
		return nil, false, fmt.Errorf("%w: the reply is not a members list", ErrMembersUnavailable)
	}
	if r.Group != group {
		return nil, false, fmt.Errorf("%w: the reply is for group %q, not %q", ErrMembersUnavailable, r.Group, group)
	}
	out := make([]string, 0, len(r.Members))
	for _, m := range r.Members {
		a, err := mail.ParseAddress(m)
		if err != nil || a.Name != "" || !strings.EqualFold(a.Address, m) {
			return nil, false, fmt.Errorf("%w: the reply holds something that is not an address", ErrMembersUnavailable)
		}
		out = append(out, strings.ToLower(a.Address))
	}
	return out, false, nil
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
