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
		name             string
		envs             Envs
		expectedLogLevel logrus.Level
	}{
		{
			name:             "Should return default log level when env is not set",
			expectedLogLevel: logrus.InfoLevel,
		},
		{
			name: "Should return default log level when env has invalid value",
			envs: Envs{
				"SCANNER_LOG_LEVEL": "unknown_level",
			},
			expectedLogLevel: logrus.InfoLevel,
		},
		{
			name: "Should return log level set as env",
			envs: Envs{
				"SCANNER_LOG_LEVEL": "trace",
			},
			expectedLogLevel: logrus.TraceLevel,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			setenvs(t, tc.envs)
			assert.Equal(t, tc.expectedLogLevel, GetLogLevel())
		})
	}
}

func TestGetAPIConfig(t *testing.T) {
	testCases := []struct {
		name           string
		envs           Envs
		expectedConfig APIConfig
	}{
		{
			name: "Should return default config",
			expectedConfig: APIConfig{
				Addr:         ":8080",
				ReadTimeout:  parseDuration(t, "15s"),
				WriteTimeout: parseDuration(t, "15s"),
			},
		},
		{
			name: "Should overwrite default config with envs",
			envs: map[string]string{
				"SCANNER_API_SERVER_ADDR":            ":7654",
				"SCANNER_API_SERVER_TLS_CERTIFICATE": "/certs/tls.crt",
				"SCANNER_API_SERVER_TLS_KEY":         "/certs/tls.key",
				"SCANNER_API_SERVER_READ_TIMEOUT":    "1h17m",
				"SCANNER_API_SERVER_WRITE_TIMEOUT":   "2h5m",
			},
			expectedConfig: APIConfig{
				Addr:           ":7654",
				TLSCertificate: "/certs/tls.crt",
				TLSKey:         "/certs/tls.key",
				ReadTimeout:    parseDuration(t, "1h17m"),
				WriteTimeout:   parseDuration(t, "2h5m"),
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			setenvs(t, tc.envs)

			cfg, err := GetAPIConfig()
			require.NoError(t, err)
			assert.Equal(t, tc.expectedConfig, cfg)
		})
	}

}

func TestAPIConfig_IsTLSEnabled(t *testing.T) {
	testCases := []struct {
		name     string
		envs     Envs
		expected bool
	}{
		{
			name: "Should return true when cert and key are set",
			envs: Envs{
				"SCANNER_API_SERVER_TLS_CERTIFICATE": "/certs/tls.crt",
				"SCANNER_API_SERVER_TLS_KEY":         "/certs/tls.key",
			},
			expected: true,
		},
		{
			name: "Should return false when only cert is set",
			envs: Envs{
				"SCANNER_API_SERVER_TLS_CERTIFICATE": "/certs/tls.crt",
			},
			expected: false,
		},
		{
			name: "Should return false when only key is set",
			envs: Envs{
				"SCANNER_API_SERVER_TLS_KEY": "/certs/tls.key",
			},
			expected: false,
		},
		{
			name:     "Should return false when neither cert nor key is set",
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			setenvs(t, tc.envs)
			config, _ := GetAPIConfig()
			assert.Equal(t, tc.expected, config.IsTLSEnabled())
		})
	}
}

func TestGetTLSConfig(t *testing.T) {
	testCases := []struct {
		name           string
		envs           Envs
		expectedConfig TLSConfig
	}{
		{
			name: "Should return default config",
			expectedConfig: TLSConfig{
				InsecureSkipVerify: false,
			},
		},
		{
			name: "Should overwrite default config with envs",
			envs: Envs{
				"SCANNER_TLS_INSECURE_SKIP_VERIFY": "true",
				"SCANNER_TLS_CLIENTCAS":            "test/data/ca.crt",
			},
			expectedConfig: TLSConfig{
				InsecureSkipVerify: true},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			setenvs(t, tc.envs)
			// TODO Assert on the actual cfg and RootCAs
			_, err := GetTLSConfig()
			require.NoError(t, err)
		})
	}
}

func TestGetClairConfig(t *testing.T) {
	testCases := []struct {
		name           string
		envs           Envs
		expectedConfig ClairConfig
	}{
		{
			name: "Should return default config",
			expectedConfig: ClairConfig{
				URL: "http://harbor-harbor-clair:6060",
			},
		},
		{
			name: "Should overwrite default config with envs",
			envs: map[string]string{
				"SCANNER_CLAIR_URL": "https://demo.clair:7080",
			},
			expectedConfig: ClairConfig{
				URL: "https://demo.clair:7080",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			setenvs(t, tc.envs)
			cfg, err := GetClairConfig()
			require.NoError(t, err)
			assert.Equal(t, tc.expectedConfig, cfg)
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
