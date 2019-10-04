package etc

import (
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"testing"
	"time"
)

type Envs map[string]string

func TestGetLogLevel(t *testing.T) {
	testCases := []struct {
		Name             string
		Envs             Envs
		ExpectedLogLevel logrus.Level
	}{
		{
			Name:             "Should return default log level when env is not set",
			ExpectedLogLevel: logrus.InfoLevel,
		},
		{
			Name: "Should return default log level when env has invalid value",
			Envs: Envs{
				"SCANNER_LOG_LEVEL": "unknown_level",
			},
			ExpectedLogLevel: logrus.InfoLevel,
		},
		{
			Name: "Should return log level set as env",
			Envs: Envs{
				"SCANNER_LOG_LEVEL": "trace",
			},
			ExpectedLogLevel: logrus.TraceLevel,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			setenvs(t, tc.Envs)
			assert.Equal(t, tc.ExpectedLogLevel, GetLogLevel())
		})
	}
}

func TestGetConfig(t *testing.T) {
	testCases := []struct {
		Name           string
		Envs           map[string]string
		ExpectedConfig Config
	}{
		{
			Name: "Should return default config",
			ExpectedConfig: Config{
				APIAddr:      ":8080",
				ReadTimeout:  parseDuration(t, "15s"),
				WriteTimeout: parseDuration(t, "15s"),
				ClairURL:     "http://harbor-harbor-clair:6060",
			},
		},
		{
			Name: "Should overwrite default config with envs",
			Envs: map[string]string{
				"SCANNER_API_ADDR":                 ":7654",
				"SCANNER_CLAIR_URL":                "https://demo.clair:7080",
				"SCANNER_API_SERVER_READ_TIMEOUT":  "1h17m",
				"SCANNER_API_SERVER_WRITE_TIMEOUT": "2h5m",
			},
			ExpectedConfig: Config{
				APIAddr:      ":7654",
				ReadTimeout:  parseDuration(t, "1h17m"),
				WriteTimeout: parseDuration(t, "2h5m"),
				ClairURL:     "https://demo.clair:7080",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			setenvs(t, tc.Envs)

			cfg, err := GetConfig()
			require.NoError(t, err)

			assert.Equal(t, tc.ExpectedConfig, cfg)
		})
	}

}

func setenvs(t *testing.T, envs Envs) {
	t.Helper()
	os.Clearenv()
	for key, value := range envs {
		err := os.Setenv(key, value)
		require.NoError(t, err)
	}
}

func parseDuration(t *testing.T, s string) time.Duration {
	t.Helper()
	duration, err := time.ParseDuration(s)
	require.NoError(t, err)
	return duration
}
