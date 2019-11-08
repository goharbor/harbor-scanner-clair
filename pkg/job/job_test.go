package job

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestStatus_String(t *testing.T) {
	testCases := []struct {
		status         Status
		expectedString string
	}{
		{
			status:         0,
			expectedString: "Pending",
		},
		{
			status:         1,
			expectedString: "Running",
		},
		{
			status:         2,
			expectedString: "Finished",
		},
		{
			status:         3,
			expectedString: "Failed",
		},
		{
			status:         1,
			expectedString: "Running",
		},
		{
			status:         -1,
			expectedString: "Unknown",
		},
		{
			status:         30,
			expectedString: "Unknown",
		},
	}
	for _, tc := range testCases {
		t.Run(fmt.Sprintf("Should return %s when status equals %d", tc.expectedString, tc.status), func(t *testing.T) {
			assert.Equal(t, tc.expectedString, tc.status.String())
		})
	}
}
