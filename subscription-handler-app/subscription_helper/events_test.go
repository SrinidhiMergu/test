package subscription_helper

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestCustomTime_UnmarshalJSON(t *testing.T) {
	// Test UnmarshalJSON method of CustomTime
	tests := []struct {
		name     string
		input    string
		expected time.Time
		wantErr  bool
	}{
		{
			name:     "valid time",
			input:    "\"2024-03-15 12:00:00.000\"",
			expected: time.Date(2024, time.March, 15, 12, 0, 0, 0, time.UTC),
			wantErr:  false,
		},
		{
			name:     "invalid time format",
			input:    "\"2024-03-15 12:00:00\"",
			expected: time.Time{},
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ct CustomTime
			err := json.Unmarshal([]byte(tt.input), &ct)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, ct.Time)
			}
		})
	}
}
