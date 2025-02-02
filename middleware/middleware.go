package middleware

import (
	"crypto/subtle"
	"net/http"

	"openport-exporter/config"
)

// BasicAuth creates a middleware for HTTP Basic Authentication.
func BasicAuth(cfg *config.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// If BasicAuth is not configured, skip authentication.
			if cfg.Auth == nil {
				next.ServeHTTP(w, r)
				return
			}

			// Get the Basic Auth credentials from the request.
			username, password, ok := r.BasicAuth()
			if !ok {
				w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			// Compare the provided credentials with the configured ones using constant-time comparison.
			usernameMatch := subtle.ConstantTimeCompare([]byte(username), []byte(cfg.Auth.Basic.Username))
			passwordMatch := subtle.ConstantTimeCompare([]byte(password), []byte(cfg.Auth.Basic.Password))
			if usernameMatch != 1 || passwordMatch != 1 {
				w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
