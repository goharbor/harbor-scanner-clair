package metrics

import (
	"github.com/goharbor/harbor-scanner-clair/pkg/etc"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"net/http"
)

type Server struct {
	cfg    etc.MetricsConfig
	server *http.Server
}

func NewServer(cfg etc.MetricsConfig) *Server {
	mux := http.NewServeMux()
	mux.Handle(cfg.Endpoint, promhttp.Handler())
	return &Server{
		cfg: cfg,
		server: &http.Server{
			Addr:    cfg.Addr,
			Handler: mux,
		},
	}
}

func (s *Server) ListenAndServe() error {
	log.WithField("addr", s.cfg.Addr).Warn("Starting metrics server without TLS")
	return s.server.ListenAndServe()
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.server.Shutdown(ctx)
}
