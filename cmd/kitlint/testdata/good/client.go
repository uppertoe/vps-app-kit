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
