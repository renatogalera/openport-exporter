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
			// If BasicAuth is not configured, skip authentication
			if cfg.Auth == nil {
				next.ServeHTTP(w, r)
				return
			}

			// Get the Basic Auth credentials from the request
			username, password, ok := r.BasicAuth()
			if !ok {
				// If no credentials provided, return 401 Unauthorized
				w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			// Compare the provided credentials with the configured ones
			// Use constant-time comparison to prevent timing attacks
			usernameMatch := subtle.ConstantTimeCompare([]byte(username), []byte(cfg.Auth.Basic.Username))
			passwordMatch := subtle.ConstantTimeCompare([]byte(password), []byte(cfg.Auth.Basic.Password))

			// If credentials don't match, return 401 Unauthorized
			if usernameMatch != 1 || passwordMatch != 1 {
				w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			// If authentication is successful, call the next handler
			next.ServeHTTP(w, r)
		})
	}
}
