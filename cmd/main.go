package main

import (
	"auth/configs"
	_ "auth/docs"
	"auth/internal/auth"
	"auth/pkg/db"
	"fmt"
	"log"
	"net/http"
)

// @title Refresh token service
// @version 1.0
// @description This is a part of authentification service, that can genrate pairs of tokens

// @host localhost:8080
//@basepath /

//@securityDefinitions.apiKey AuthKey
//@in header
//@name Authorization

func main() {
	router := http.NewServeMux()

	conf := configs.LoadConfig()
	db := db.NewDB(conf)
	repo := auth.NewAuthRepo(db)
	service := auth.NewAuthService(repo)

	auth.NewAuthHandler(router, auth.AuthHandlerDeps{
		Service: service,
		Config:  conf,
	})

	server := http.Server{
		Addr:    ":8080",
		Handler: router,
	}

	fmt.Println("Server is listening on port :8080")
	err := server.ListenAndServe()
	if err != nil {
		log.Fatal(err)
	}
}
