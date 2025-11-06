package app

import (
	grpcapp "auth-service/internal/app/grpc"
	"auth-service/internal/config"
	"auth-service/internal/lib/jwt"
	"auth-service/internal/services/auth"
	"auth-service/internal/storage/kafka"
	"auth-service/internal/storage/postgres"
	"auth-service/internal/storage/redis"
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
	redisClient := redis.NewRedis(config)
	kafkaClient := kafka.New(config.KafkaBrokers)
	authService := auth.New(storage, storage, jwtService, config, redisClient, kafkaClient)

	grpcApp := grpcapp.New(authService, config.GrpcPort)
	return &App{
		GrpcSrv: grpcApp,
	}
}
