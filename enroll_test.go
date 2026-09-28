package main

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestBootstrapRejectsUnsafeTransportBeforeCreatingIdentity(t *testing.T) {
	for _, tc := range []struct {
		url      string
		insecure bool
	}{
		{"http://localhost/bootstrap", false},
		{"https://localhost", true},
		{"https://user:password@localhost", false},
		{"https://localhost?query=1", false},
		{"https://localhost#fragment", false},
	} {
		t.Run(tc.url, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "identity")
			if err := enrollAndAwait(path, tc.url, "synthetic-token", "test", tc.insecure, "sha256:synthetic-pin", time.Millisecond, time.Millisecond); err == nil {
				t.Fatal("accepted unsafe bootstrap transport")
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatalf("identity was touched: %v", err)
			}
		})
	}
}

func TestBootstrapTLSAndRedirects(t *testing.T) {
	var delivered atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		delivered.Add(1)
		w.Write([]byte(`{}`))
	}))
	defer target.Close()
	var requests atomic.Int32
	origin := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		switch r.URL.Path {
		case "/307":
			http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
		case "/308":
			http.Redirect(w, r, target.URL, http.StatusPermanentRedirect)
		default:
			w.Write([]byte(`{"state":"pending"}`))
		}
	}))
	origin.Config.ErrorLog = log.New(io.Discard, "", 0)
	origin.StartTLS()
	defer origin.Close()
	c := bootstrapClient()
	defer c.CloseIdleConnections()
	if _, err := bootCall(c, "POST", origin.URL, map[string]any{"join_token": "synthetic-token"}); err == nil {
		t.Fatal("accepted untrusted TLS certificate")
	}
	if requests.Load() != 0 {
		t.Fatal("sent token before authenticating TLS")
	}
	// Supply this test CA exactly as a trusted enterprise root would be supplied.
	roots := x509.NewCertPool()
	roots.AddCert(origin.Certificate())
	c.Transport.(*http.Transport).TLSClientConfig = &tls.Config{RootCAs: roots}
	if _, err := bootCall(c, "POST", origin.URL, map[string]any{"join_token": "synthetic-token"}); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/307", "/308"} {
		if _, err := bootCall(c, "POST", origin.URL+path, map[string]any{"join_token": "synthetic-token"}); err == nil {
			t.Fatal("accepted redirect")
		}
	}
	if _, err := bootCall(c, "POST", target.URL, map[string]any{"join_token": "synthetic-token"}); err == nil {
		t.Fatal("accepted HTTP")
	}
	if delivered.Load() != 0 {
		t.Fatal("token reached unverified redirect target")
	}
}
