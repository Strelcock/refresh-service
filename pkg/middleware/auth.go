package middleware

import (
	"auth/configs"
	"auth/pkg/jwt"
	"context"
	"net/http"
	"strings"
	"time"
)

type key string

const (
	JTIKey key = "JTIKey"
	UidKey key = "UidKey"
)

func writeUnauthed(w http.ResponseWriter) {
	w.WriteHeader(http.StatusUnauthorized)
	w.Write([]byte(http.StatusText(http.StatusUnauthorized)))
}

func Authentificator(next http.Handler, config *configs.Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authedHeader := r.Header.Get("Authorization")

		if !strings.HasPrefix(authedHeader, "Bearer ") {
			writeUnauthed(w)
			return
		}

		token := strings.TrimPrefix(authedHeader, "Bearer ")
		isValid, data := jwt.NewJWT(config.Secret).Parse(token)
		if !isValid {
			writeUnauthed(w)
			return
		}

		if time.Now().Unix() >= data.Exp {
			writeUnauthed(w)
			return
		}

		ctx := context.WithValue(r.Context(), JTIKey, data.Jti)
		ctx = context.WithValue(ctx, UidKey, data.Sub)
		req := r.WithContext(ctx)
		next.ServeHTTP(w, req)
	})
}
