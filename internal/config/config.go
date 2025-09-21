package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	PostgresDsn      string
	RedisAddress     string
	RedisPassword    string
	JwtSecret        string
	TokenExpireHours time.Duration
	GrpcPort         int
	KafkaBrokers     string
}

func LoadConfig() (*Config, error) {
	tokenExpireHours, err := strconv.Atoi(os.Getenv("TOKEN_EXPIRE_HOURS"))
	if err != nil {
		panic("Could not parse TOKEN_EXPIRE_HOURS")
	}

	grpcPort, err := strconv.Atoi(os.Getenv("GRPC_PORT"))
	if err != nil {
		panic("Could not parse GRPC_PORT")
	}

	return &Config{
		PostgresDsn:      os.Getenv("POSTGRES_DSN"),
		RedisAddress:     os.Getenv("REDIS_ADDRESS"),
		RedisPassword:    os.Getenv("REDIS_PASSWORD"),
		JwtSecret:        os.Getenv("JWT_SECRET"),
		TokenExpireHours: time.Duration(tokenExpireHours) * time.Hour,
		GrpcPort:         grpcPort,
		KafkaBrokers:     os.Getenv("KAFKA_BROKERS"),
	}, nil
}
