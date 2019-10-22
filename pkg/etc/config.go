package etc

import (
	"crypto/x509"
	"fmt"
	"github.com/caarlos0/env/v6"
	"github.com/goharbor/harbor-scanner-clair/pkg/model/harbor"
	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"os"
	"strings"
	"time"
)

type APIConfig struct {
	Addr           string        `env:"SCANNER_API_SERVER_ADDR" envDefault:":8080"`
	TLSCertificate string        `env:"SCANNER_API_SERVER_TLS_CERTIFICATE"`
	TLSKey         string        `env:"SCANNER_API_SERVER_TLS_KEY"`
	ReadTimeout    time.Duration `env:"SCANNER_API_SERVER_READ_TIMEOUT" envDefault:"15s"`
	WriteTimeout   time.Duration `env:"SCANNER_API_SERVER_WRITE_TIMEOUT" envDefault:"15s"`
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

func GetAPIConfig() (cfg APIConfig, err error) {
	err = env.Parse(&cfg)
	return
}

func GetTLSConfig() (cfg TLSConfig, err error) {
	err = env.Parse(&cfg)
	if err != nil {
		return
	}

	cfg.RootCAs, err = x509.SystemCertPool()
	if err != nil {
		log.WithError(err).Warn("Error while loading system root CAs")
	}
	if cfg.RootCAs == nil {
		log.Debug("Creating empty root CAs pool")
		cfg.RootCAs = x509.NewCertPool()
	}

	for _, certFile := range cfg.ClientCAs {
		certs, err := ioutil.ReadFile(strings.TrimSpace(certFile))
		if err != nil {
			return cfg, fmt.Errorf("failed to append %q to root CAs pool: %v", certFile, err)
		}

		if ok := cfg.RootCAs.AppendCertsFromPEM(certs); !ok {
			return cfg, fmt.Errorf("failed to append %q to root CAs pool: %v", certFile, err)
		}
		log.WithField("cert", certFile).Debug("Client CA appended to root CAs pool")
	}

	return
}

func GetClairConfig() (cfg ClairConfig, err error) {
	err = env.Parse(&cfg)
	return
}

func GetScannerMetadata() harbor.Scanner {
	return harbor.Scanner{
		Name:    "Clair",
		Vendor:  "CoreOS",
		Version: "2.x",
	}
}
