package etc

import (
	"github.com/caarlos0/env/v6"
	"github.com/sirupsen/logrus"
	"os"
	"time"
)

type Config struct {
	APIAddr      string        `env:"SCANNER_API_ADDR" envDefault:":8080"`
	ReadTimeout  time.Duration `env:"SCANNER_API_SERVER_READ_TIMEOUT" envDefault:"15s"`
	WriteTimeout time.Duration `env:"SCANNER_API_SERVER_WRITE_TIMEOUT" envDefault:"15s"`
	ClairURL     string        `env:"SCANNER_CLAIR_URL" envDefault:"http://harbor-harbor-clair:6060"`
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
	return
}
