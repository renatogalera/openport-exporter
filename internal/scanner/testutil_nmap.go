package scanner

import (
    "os/exec"
    "testing"
)

// skipIfNoNmap skips tests that require creating an nmap.Scanner
// when the nmap binary is not available in PATH (common in CI).
func skipIfNoNmap(t *testing.T) {
    t.Helper()
    if _, err := exec.LookPath("nmap"); err != nil {
        t.Skip("skipping: nmap binary not found in PATH")
    }
}

