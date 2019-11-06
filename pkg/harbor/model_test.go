package harbor

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestSeverity_MarshalJSON(t *testing.T) {
	testCases := []struct {
		severity     Severity
		expectedJSON []byte
	}{
		{
			severity:     SevNone,
			expectedJSON: []byte("\"None\""),
		},
		{
			severity:     SevUnknown,
			expectedJSON: []byte("\"Unknown\""),
		},
		{
			severity:     SevNegligible,
			expectedJSON: []byte("\"Negligible\""),
		},
		{
			severity:     SevLow,
			expectedJSON: []byte("\"Low\""),
		},
		{
			severity:     SevMedium,
			expectedJSON: []byte("\"Medium\""),
		},
		{
			severity:     SevCritical,
			expectedJSON: []byte("\"Critical\""),
		},
	}
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("Should marshal %s to %s", tc.severity.String(), string(tc.expectedJSON)), func(t *testing.T) {
			actualJSON, err := tc.severity.MarshalJSON()
			assert.NoError(t, err)
			assert.Equal(t, string(tc.expectedJSON), string(actualJSON))
		})
	}
}

func TestSeverity_UnmarshalJSON(t *testing.T) {
	testCases := []struct {
		severityJSON     []byte
		expectedSeverity Severity
	}{
		{
			severityJSON:     []byte("\"None\""),
			expectedSeverity: SevNone,
		},
		{
			severityJSON:     []byte("\"Unknown\""),
			expectedSeverity: SevUnknown,
		},
		{
			severityJSON:     []byte("\"Negligible\""),
			expectedSeverity: SevNegligible,
		},
		{
			severityJSON:     []byte("\"Low\""),
			expectedSeverity: SevLow,
		},
		{
			severityJSON:     []byte("\"Medium\""),
			expectedSeverity: SevMedium,
		},
		{
			severityJSON:     []byte("\"Critical\""),
			expectedSeverity: SevCritical,
		},
	}
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("Should unmarshal %s to %s", string(tc.severityJSON), tc.expectedSeverity.String()), func(t *testing.T) {
			var severity Severity
			err := severity.UnmarshalJSON(tc.severityJSON)
			require.NoError(t, err)
			assert.Equal(t, tc.expectedSeverity, severity)
		})
	}
}
