package serve

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRequestLogRecordsNoPersonalData(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewJSONHandler(&buf, nil))
	mux := http.NewServeMux()
	mux.HandleFunc("GET /people/{id}", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
	h := RequestLog(log, mux)
	r := httptest.NewRequest("GET", "/people/ann-smith?email=ann@rch.org.au", nil)
	r.Header.Set("Remote-Email", "ann@rch.org.au")
	r.Header.Set("Cookie", "vps_auth_session=secret")
	h.ServeHTTP(httptest.NewRecorder(), r)
	out := buf.String()
	for _, leaked := range []string{"ann", "rch.org.au", "secret", "email="} {
		if strings.Contains(out, leaked) {
			t.Errorf("log contains %q: %s", leaked, out)
		}
	}
	if !strings.Contains(out, `"route":"GET /people/{id}"`) || !strings.Contains(out, `"status":204`) {
		t.Errorf("log lacks route or status: %s", out)
	}
}
