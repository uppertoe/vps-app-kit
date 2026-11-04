package good

import (
	"context"
	"net/http"
)

func f(ctx context.Context, c *http.Client) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.example.org", nil)
	if err != nil {
		return err
	}
	_, err = c.Do(req)
	return err
}

func h(w http.ResponseWriter, r *http.Request) { http.Error(w, "x", http.StatusTeapot) }

// A *http.Client handed over from egress.New is the intended pattern.
type server struct {
	http *http.Client
}

func use(s server) *http.Client { return s.http }
