package proxy

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestCredentials(t *testing.T) {
	creds := Credentials{
		Username:   "admin",
		Password:   "secret",
		PrivateKey: []byte("ssh-key"),
		APIKey:     "api-key",
		Token:      "token",
	}

	assert.Equal(t, "admin", creds.Username)
	assert.Equal(t, "secret", creds.Password)
	assert.Equal(t, []byte("ssh-key"), creds.PrivateKey)
	assert.Equal(t, "api-key", creds.APIKey)
	assert.Equal(t, "token", creds.Token)
}

func TestOperation(t *testing.T) {
	op := &Operation{
		Action:       "get-config",
		ResourcePath: "/running-config",
		Parameters: map[string]interface{}{
			"format": "json",
		},
		Data: map[string]string{"key": "value"},
	}

	assert.Equal(t, "get-config", op.Action)
	assert.Equal(t, "/running-config", op.ResourcePath)
	assert.Equal(t, "json", op.Parameters["format"])
	assert.NotNil(t, op.Data)
}

func TestOperationResult(t *testing.T) {
	result := &OperationResult{
		Success:    true,
		Output:     "config output",
		Data:       map[string]interface{}{"hostname": "router1"},
		Error:      "",
		Duration:   150 * time.Millisecond,
		StatusCode: 200,
	}

	assert.True(t, result.Success)
	assert.Equal(t, "config output", result.Output)
	assert.Equal(t, 150*time.Millisecond, result.Duration)
	assert.Equal(t, 200, result.StatusCode)
	assert.Empty(t, result.Error)
}

func TestOperationResult_Error(t *testing.T) {
	result := &OperationResult{
		Success:    false,
		Output:     "",
		Error:      "connection refused",
		Duration:   50 * time.Millisecond,
		StatusCode: 0,
	}

	assert.False(t, result.Success)
	assert.Equal(t, "connection refused", result.Error)
}
