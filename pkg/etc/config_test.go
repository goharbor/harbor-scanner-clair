package etc

import (
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"testing"
)

func TestGetConfig(t *testing.T) {
	testCases := []struct {
		Name           string
		Envs           map[string]string
		ExpectedConfig Config
	}{
		{
			Name: "Should return default config",
			ExpectedConfig: Config{
				APIAddr:  ":8080",
				ClairURL: "http://harbor-harbor-clair:6060",
			},
		},
		{
			Name: "Should overwrite default config with envs",
			Envs: map[string]string{
				"SCANNER_API_ADDR":  ":7654",
				"SCANNER_CLAIR_URL": "https://demo.clair:7080",
			},
			ExpectedConfig: Config{
				APIAddr:  ":7654",
				ClairURL: "https://demo.clair:7080",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			os.Clearenv()
			for key, value := range tc.Envs {
				err := os.Setenv(key, value)
				require.NoError(t, err)
			}

			cfg, err := GetConfig()
			require.NoError(t, err)

			assert.Equal(t, tc.ExpectedConfig, cfg)
		})
	}

}
