package mocktarget

import (
	"net/http"
	"net/http/httptest"
)

// New returns an in-process HTTP server that plays a deliberately vulnerable
// target, so detection can be exercised end-to-end without a real backend. It
// starts immediately and must be closed by the caller (defer srv.Close()).
//
// Behavior is scripted to match the two shipped rules:
//   - /users/...  always returns 200 with an "email" field  -> triggers BOLA-001
//   - /admin/...  returns 200 when Authorization is empty    -> triggers AUTH-BYPASS-001
//     (otherwise 403)
func New() *httptest.Server {
	mux := http.NewServeMux()

	mux.HandleFunc("/users/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":43,"email":"victim@example.com"}`))
	})

	mux.HandleFunc("/admin/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"admin":true}`))
			return
		}
		w.WriteHeader(http.StatusForbidden)
	})

	return httptest.NewServer(mux)
}
