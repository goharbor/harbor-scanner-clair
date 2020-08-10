package api

import (
	"context"
	"crypto/tls"
	"net/http"

	"github.com/goharbor/harbor-scanner-clair/pkg/etc"
	log "github.com/sirupsen/logrus"
)

type Server struct {
	config etc.APIConfig
	server *http.Server
}

func NewServer(config etc.APIConfig, handler http.Handler) *Server {
	return &Server{
		config: config,
		server: &http.Server{
			Handler:      handler,
			Addr:         config.Addr,
			ReadTimeout:  config.ReadTimeout,
			WriteTimeout: config.WriteTimeout,
			IdleTimeout:  config.IdleTimeout,
		},
	}
}

func (s *Server) ListenAndServe() {
	go func() {
		if err := s.listenAndServe(); err != http.ErrServerClosed {
			log.Fatalf("Error: %v", err)
		}
		log.Trace("API server stopped listening for incoming connections")
	}()
}

func (s *Server) listenAndServe() error {
	if s.config.IsTLSEnabled() {
		log.WithFields(log.Fields{
			"certificate": s.config.TLSCertificate,
			"key":         s.config.TLSKey,
			"addr":        s.config.Addr,
		}).Debug("Starting API server with TLS")
		return s.server.ListenAndServeTLS(s.config.TLSCertificate, s.config.TLSKey)
	}

	s.server.TLSConfig = &tls.Config{
		PreferServerCipherSuites: true,
		CurvePreferences: []tls.CurveID{
			tls.CurveP256,
			tls.X25519,
		},
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}

	log.WithField("addr", s.config.Addr).Warn("Starting API server without TLS")
	return s.server.ListenAndServe()
}

func (s *Server) Shutdown(ctx context.Context) {
	log.Trace("API server shutdown started")
	if err := s.server.Shutdown(context.Background()); err != nil {
		log.WithError(err).Error("Error while shutting down API server")
	}
	log.Trace("API server shutdown completed")
}
