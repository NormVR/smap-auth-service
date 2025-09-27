package redis

import (
	"auth-service/internal/config"
	"context"
	"log"
	"time"

	"github.com/redis/go-redis/v9"
)

type Redis struct {
	redisClient *redis.Client
}

func NewRedis(config *config.Config) *Redis {
	return &Redis{
		redisClient: redis.NewClient(&redis.Options{
			Addr:     config.RedisAddress,
			Password: config.RedisPassword,
			DB:       0,
		}),
	}
}

func (app *Redis) StoreToken(key string, value int64, ttl time.Duration) {
	ctx := context.Background()

	if err := app.redisClient.Ping(ctx).Err(); err != nil {
		log.Printf("redis ping failed: %v", err)
		return
	}

	log.Printf("Trying to add token %s to redis with value %d with duration %s: ", key, value, ttl)
	err := app.redisClient.Set(ctx, key, value, ttl).Err()
	if err != nil {
		log.Println("[redis] failed to store token")
	}
}

func (app *Redis) RemoveToken(key string) error {
	ctx := context.Background()

	if err := app.redisClient.Ping(ctx).Err(); err != nil {
		return err
	}

	if err := app.redisClient.Del(ctx, key).Err(); err != nil {
		return err
	}

	return nil
}
