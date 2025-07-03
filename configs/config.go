package configs

import (
	"log"
	"os"

	"github.com/joho/godotenv"
)

type Config struct {
	AuthConfig
	DBConfig
}

type AuthConfig struct {
	Secret string
}

type DBConfig struct {
	DSN string
}

func LoadConfig() *Config {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file, using default config")
	}

	return &Config{
		AuthConfig: AuthConfig{
			Secret: os.Getenv("SECRET"),
		},
		DBConfig: DBConfig{
			DSN: os.Getenv("DSN"),
		},
	}
}
