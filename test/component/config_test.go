package component

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/caarlos0/env/v6"
	"github.com/docker/docker/api/types"
	"net/url"
)

type Config struct {
	Registry           RegistryConfig
	ArtifactRepository string `env:"TEST_ARTIFACT_REPOSITORY" envDefault:"alpine"`
	ArtifactTag        string `env:"TEST_ARTIFACT_TAG" envDefault:"3.10.2"`
	ScannerURL         string `env:"TEST_SCANNER_URL" envDefault:"http://localhost:8080"`
}

type RegistryConfig struct {
	URL      string `env:"TEST_REGISTRY_URL" envDefault:"https://registry:5443"`
	Username string `env:"TEST_REGISTRY_USERNAME" envDefault:"testuser"`
	Password string `env:"TEST_REGISTRY_PASSWORD" envDefault:"testpassword"`
}

func (c RegistryConfig) GetRegistryAuth() (auth string, err error) {
	authConfig := types.AuthConfig{
		Username: c.Username,
		Password: c.Password,
	}
	encodedJSON, err := json.Marshal(authConfig)
	if err != nil {
		return "", err
	}
	auth = base64.URLEncoding.EncodeToString(encodedJSON)
	return
}

func (c RegistryConfig) GetBasicAuthorization() string {
	return fmt.Sprintf("Basic %s", base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", c.Username, c.Password))))
}

func (c RegistryConfig) GetRegistryHost() (string, error) {
	registryURL, err := url.Parse(c.URL)
	if err != nil {
		return "", err
	}
	return registryURL.Host, nil
}

func GetConfig() (config Config, err error) {
	err = env.Parse(&config)
	return
}
