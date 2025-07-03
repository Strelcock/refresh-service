package generator

import (
	"crypto/rand"
	"encoding/base64"
)

func JTI() string {
	bytes := make([]byte, 8)
	_, err := rand.Read(bytes)
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(bytes)
}
