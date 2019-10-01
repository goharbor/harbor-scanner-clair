package etc

import (
	"github.com/caarlos0/env/v6"
)

type Config struct {
	APIAddr  string `env:"SCANNER_API_ADDR" envDefault:":8080"`
	ClairURL string `env:"SCANNER_CLAIR_URL" envDefault:"http://harbor-harbor-clair:6060"`
}

func GetConfig() (cfg Config, err error) {
	err = env.Parse(&cfg)
	return
}
