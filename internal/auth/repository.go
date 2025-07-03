package auth

import (
	"auth/internal/models"
	"auth/pkg/db"
)

type AuthRepo struct {
	*db.Db
}

func NewAuthRepo(db *db.Db) *AuthRepo {
	return &AuthRepo{db}
}

func (ar *AuthRepo) Create(token *models.Refresh) error {
	err := ar.DB.Create(token).Error
	if err != nil {
		return err
	}

	updates := map[string]any{
		"used": true,
	}
	err = ar.DB.Model(models.Refresh{}).
		Where("uid = ? AND jti != ?", token.UID, token.Jti).
		Updates(updates).Error

	if err != nil {
		return err
	}

	return nil
}

func (ar *AuthRepo) GetByJTI(jti string) (*models.Refresh, error) {
	var result models.Refresh
	err := ar.DB.First(&result, "jti = ? and used = false", jti).Error
	if err != nil {
		return nil, err
	}

	return &result, err
}

func (ar *AuthRepo) DeleteByUID(uid string) error {
	err := ar.DB.Delete(&models.Refresh{}, "uid = ?", uid).Error
	if err != nil {
		return err
	}
	return nil
}
