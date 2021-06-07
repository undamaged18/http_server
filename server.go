package http_server

import (
"crypto/tls"
"github.com/gorilla/mux"
"golang.org/x/crypto/acme/autocert"
"net/http"
"strings"
"time"
)

type server struct {
	production  bool
	server      *http.Server
	Handler     *mux.Router
	certManager *autocert.Manager
	Config struct {
		KeyFile string
		CertFile string
	}
}

var s server

func init() {
	s.certManager = &autocert.Manager{
		Prompt:          autocert.AcceptTOS,
		Cache:           autocert.DirCache("certs"),
	}
	s.Handler = mux.NewRouter()
	s.server = &http.Server{
		Addr:    ":443",
		Handler: http.TimeoutHandler(caselessMatcher(s.Handler), time.Second*5, ""),
		TLSConfig:         &tls.Config{
			PreferServerCipherSuites: true,
			MinVersion:               tls.VersionTLS12,
			CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			},
		},
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    http.DefaultMaxHeaderBytes,
	}
}

func New(production bool) *server {
	s.production = production
	return &s
}

func (s *server) ListenAndServe() error {
	return http.ListenAndServe(":80", s.certManager.HTTPHandler(s.Handler))
}

func (s *server) ListenAndServeTLS() error {
	var certFile, keyFile string
	if s.production {
		s.server.Handler = s.certManager.HTTPHandler(s.server.Handler)
	} else {
		certFile = s.Config.CertFile
		keyFile = s.Config.KeyFile
	}
	return s.server.ListenAndServeTLS(certFile, keyFile)
}

func caselessMatcher(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.URL.Path = strings.ToLower(r.URL.Path)
		next.ServeHTTP(w, r)
	})
}
