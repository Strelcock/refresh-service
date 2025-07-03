package di

import "auth/internal/models"

type IAuthRepo interface {
	Create(token *models.Refresh) error
	GetByJTI(jti string) (*models.Refresh, error)
	DeleteByUID(uid string) error
}
