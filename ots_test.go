package ots

import (
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGenerateOTS(t *testing.T) {
	for i := 0; i < 32; i++ {
		msg := sha256.Sum256(append([]byte("some message"), byte(i)))
		s, err := GenerateOTS(nil, msg)
		require.NoError(t, err)
		ok := s.Verify()
		require.True(t, ok)
	}

}
