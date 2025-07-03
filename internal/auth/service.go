package auth

import (
	"auth/internal/di"
	"auth/internal/models"

	"golang.org/x/crypto/bcrypt"
)

type AuthService struct {
	Repo di.IAuthRepo
}

func NewAuthService(repo di.IAuthRepo) *AuthService {
	return &AuthService{Repo: repo}
}

func (as *AuthService) Create(token *models.Refresh) error {
	hashedToken, err := bcrypt.GenerateFromPassword([]byte(token.Hash), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	token.Hash = string(hashedToken)
	err = as.Repo.Create(token)
	if err != nil {
		return err
	}

	return nil
}

func (as *AuthService) CheckRefresh(jti string, oldRefresh string) (*models.Refresh, error) {
	token, err := as.Repo.GetByJTI(jti)
	if err != nil {
		return nil, err
	}

	err = bcrypt.CompareHashAndPassword([]byte(token.Hash), []byte(oldRefresh))
	if err != nil {
		return nil, err
	}

	return token, nil
}

func (as *AuthService) Delete(uid string) error {
	err := as.Repo.DeleteByUID(uid)
	if err != nil {
		return err
	}
	return nil
}
