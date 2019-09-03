package etc

import "os"

type Config struct {
	Addr     string
	ClairURL string
}

func GetConfig() (*Config, error) {
	cfg := &Config{
		Addr:     ":8080",
		ClairURL: "http://harbor-harbor-clair:6060",
	}
	if addr, ok := os.LookupEnv("SCANNER_API_ADDR"); ok {
		cfg.Addr = addr
	}
	if clairURL, ok := os.LookupEnv("SCANNER_CLAIR_URL"); ok {
		cfg.ClairURL = clairURL
	}
	return cfg, nil
}
