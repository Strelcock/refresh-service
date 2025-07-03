package jwt

import (
	"github.com/golang-jwt/jwt/v5"
)

type JWTData struct {
	Sub string
	Jti string
	Exp int64
}

type JWT struct {
	Secret string
}

func NewJWT(secret string) *JWT {
	return &JWT{Secret: secret}
}

func (j *JWT) Create(data JWTData) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"sub": data.Sub,
		"jti": data.Jti,
		"exp": data.Exp,
	})

	singedToken, err := token.SignedString([]byte(j.Secret))
	if err != nil {
		return "", err
	}

	return singedToken, nil
}

func (j *JWT) Parse(token string) (bool, *JWTData) {
	parsedToken, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		return []byte(j.Secret), nil
	})

	if err != nil {
		return false, nil
	}

	sub := parsedToken.Claims.(jwt.MapClaims)["sub"]
	jti := parsedToken.Claims.(jwt.MapClaims)["jti"]
	exp := parsedToken.Claims.(jwt.MapClaims)["exp"]

	return true, &JWTData{
		Sub: sub.(string),
		Jti: jti.(string),
		Exp: int64(exp.(float64)),
	}
}
