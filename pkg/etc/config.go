package etc

import (
	"crypto/x509"
	"fmt"
	"github.com/caarlos0/env/v6"
	"github.com/goharbor/harbor-scanner-clair/pkg/harbor"
	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"os"
	"strings"
	"time"
)

type Config struct {
	API   APIConfig
	TLS   TLSConfig
	Clair ClairConfig
	Store Store
}

type APIConfig struct {
	Addr           string        `env:"SCANNER_API_SERVER_ADDR" envDefault:":8080"`
	TLSCertificate string        `env:"SCANNER_API_SERVER_TLS_CERTIFICATE"`
	TLSKey         string        `env:"SCANNER_API_SERVER_TLS_KEY"`
	ReadTimeout    time.Duration `env:"SCANNER_API_SERVER_READ_TIMEOUT" envDefault:"15s"`
	WriteTimeout   time.Duration `env:"SCANNER_API_SERVER_WRITE_TIMEOUT" envDefault:"15s"`
	IdleTimeout    time.Duration `env:"SCANNER_API_SERVER_IDLE_TIMEOUT" envDefault:"60s"`
}

func (c *APIConfig) IsTLSEnabled() bool {
	return c.TLSCertificate != "" && c.TLSKey != ""
}

type TLSConfig struct {
	ClientCAs          []string `env:"SCANNER_TLS_CLIENTCAS"`
	InsecureSkipVerify bool     `env:"SCANNER_TLS_INSECURE_SKIP_VERIFY" envDefault:"false"`

	RootCAs *x509.CertPool
}

type ClairConfig struct {
	URL string `env:"SCANNER_CLAIR_URL" envDefault:"http://harbor-harbor-clair:6060"`
}

type Store struct {
	RedisURL      string        `env:"SCANNER_STORE_REDIS_URL" envDefault:"redis://harbor-harbor-redis:6379"`
	Namespace     string        `env:"SCANNER_STORE_REDIS_NAMESPACE" envDefault:"harbor.scanner.clair:store"`
	PoolMaxActive int           `env:"SCANNER_STORE_REDIS_POOL_MAX_ACTIVE" envDefault:"5"`
	PoolMaxIdle   int           `env:"SCANNER_STORE_REDIS_POOL_MAX_IDLE" envDefault:"5"`
	ScanJobTTL    time.Duration `env:"SCANNER_STORE_REDIS_SCAN_JOB_TTL" envDefault:"1h"`
}

func GetLogLevel() logrus.Level {
	if value, ok := os.LookupEnv("SCANNER_LOG_LEVEL"); ok {
		level, err := logrus.ParseLevel(value)
		if err != nil {
			return logrus.InfoLevel
		}
		return level
	}
	return logrus.InfoLevel
}

func GetConfig() (cfg Config, err error) {
	err = env.Parse(&cfg)
	if err != nil {
		return
	}

	cfg.TLS.RootCAs, err = x509.SystemCertPool()
	if err != nil {
		log.WithError(err).Warn("Error while loading system root CAs")
	}
	if cfg.TLS.RootCAs == nil {
		log.Debug("Creating empty root CAs pool")
		cfg.TLS.RootCAs = x509.NewCertPool()
	}

	for _, certFile := range cfg.TLS.ClientCAs {
		certs, err := ioutil.ReadFile(strings.TrimSpace(certFile))
		if err != nil {
			return cfg, fmt.Errorf("failed to append %q to root CAs pool: %v", certFile, err)
		}

		if ok := cfg.TLS.RootCAs.AppendCertsFromPEM(certs); !ok {
			return cfg, fmt.Errorf("failed to append %q to root CAs pool: %v", certFile, err)
		}
		log.WithField("cert", certFile).Debug("Client CA appended to root CAs pool")
	}

	return
}

func GetScannerMetadata() harbor.Scanner {
	return harbor.Scanner{
		Name:    "Clair",
		Vendor:  "CoreOS",
		Version: "2.x",
	}
}
