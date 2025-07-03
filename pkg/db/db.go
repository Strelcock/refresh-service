package db

import (
	"auth/configs"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type Db struct {
	*gorm.DB
}

func NewDB(config *configs.Config) *Db {
	time.Sleep(5 * time.Second)
	db, err := gorm.Open(postgres.Open(config.DSN), &gorm.Config{})
	if err != nil {
		panic(err)
	}

	return &Db{db}
}
