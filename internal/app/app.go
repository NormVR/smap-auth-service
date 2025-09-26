package app

import (
	grpcapp "auth-service/internal/app/grpc"
	"auth-service/internal/config"
	"auth-service/internal/lib/jwt"
	"auth-service/internal/services/auth"
	"auth-service/internal/storage/postgres"
)

type App struct {
	GrpcSrv *grpcapp.App
}

func New(
	config *config.Config,
) *App {
	storage, err := postgres.New(config.PostgresDsn)
	if err != nil {
		panic(err)
	}

	jwtService := jwt.NewJwtService([]byte(config.JwtSecret), config.TokenExpireHours)
	authService := auth.New(storage, storage, jwtService)

	grpcApp := grpcapp.New(authService, config.GrpcPort)
	return &App{
		GrpcSrv: grpcApp,
	}
}
