package generator

import (
	"crypto/rand"
	"encoding/base64"
)

func Token() string {
	bytes := make([]byte, 32)
	_, err := rand.Read(bytes)
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(bytes)
}
