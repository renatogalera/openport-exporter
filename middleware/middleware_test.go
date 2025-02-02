package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/renatogalera/openport-exporter/config"
)

func TestBasicAuth(t *testing.T) {
	// Define test cases
	testCases := []struct {
		name           string
		config         *config.Config
		username       string
		password       string
		expectedStatus int
	}{
		{
			name:           "No auth configured",
			config:         &config.Config{},
			username:       "",
			password:       "",
			expectedStatus: http.StatusOK,
		},
		{
			name: "Correct credentials",
			config: &config.Config{
				Auth: &config.AuthConfig{
					Basic: config.BasicAuthConfig{
						Username: "admin",
						Password: "secret",
					},
				},
			},
			username:       "admin",
			password:       "secret",
			expectedStatus: http.StatusOK,
		},
		{

			name: "Incorrect username",
			config: &config.Config{
				Auth: &config.AuthConfig{
					Basic: config.BasicAuthConfig{
						Username: "admin",
						Password: "secret",
					},
				},
			},
			username:       "wrong",
			password:       "secret",
			expectedStatus: http.StatusUnauthorized,
		},
		{

			name: "Incorrect password",
			config: &config.Config{
				Auth: &config.AuthConfig{
					Basic: config.BasicAuthConfig{
						Username: "admin",
						Password: "secret",
					},
				},
			},
			username:       "admin",
			password:       "wrong",
			expectedStatus: http.StatusUnauthorized,
		},
		{

			name: "No credentials provided",
			config: &config.Config{
				Auth: &config.AuthConfig{
					Basic: config.BasicAuthConfig{
						Username: "admin",
						Password: "secret",
					},
				},
			},
			username:       "",
			password:       "",
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a test handler that always returns 200 OK
			testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			// Create the middleware
			middleware := BasicAuth(tc.config)

			// Create a test server
			server := httptest.NewServer(middleware(testHandler))
			defer server.Close()

			// Create a new request
			req, err := http.NewRequest("GET", server.URL, nil)
			if err != nil {
				t.Fatal(err)
			}

			// Set Basic Auth credentials if provided
			if tc.username != "" || tc.password != "" {
				req.SetBasicAuth(tc.username, tc.password)
			}

			// Send the request
			client := &http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			// Check the response status
			if resp.StatusCode != tc.expectedStatus {
				t.Errorf("Expected status %d, got %d", tc.expectedStatus, resp.StatusCode)
			}
		})
	}
}
