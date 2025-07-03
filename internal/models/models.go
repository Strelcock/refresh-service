package models

type Refresh struct {
	ID        uint `gorm:"primarykey"`
	UID       string
	Hash      string
	UserAgent string
	IP        string
	Used      bool
	Jti       string
}
