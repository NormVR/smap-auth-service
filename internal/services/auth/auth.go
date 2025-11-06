package auth

import (
	"auth-service/internal/config"
	domain_errors "auth-service/internal/domain/errors"
	"auth-service/internal/domain/models"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/google/uuid"
	"github.com/segmentio/kafka-go"
	"golang.org/x/crypto/bcrypt"
)

type Auth struct {
	userSaver    UserSaver
	userProvider UserProvider
	jwtService   TokenProvider
	config       *config.Config
	redis        Cache
	kafka        MessageBroker
}

type UserSaver interface {
	SaveUser(
		ctx context.Context,
		email string,
		passHash []byte,
	) (uuid.UUID, error)
}

type UserProvider interface {
	GetUser(ctx context.Context, email string) (*models.User, error)
}

type Cache interface {
	StoreToken(key string, value uuid.UUID, ttl time.Duration)
	RemoveToken(key string) error
}

type TokenProvider interface {
	NewToken(user *models.User) (string, time.Duration, error)
	ValidateToken(tokenString string) uuid.UUID
}

type MessageBroker interface {
	Produce(msg kafka.Message) error
}

type UserCreatedEvent struct {
	UserID    uuid.UUID `json:"user_id"`
	Username  string    `json:"username"`
	CreatedAt time.Time `json:"created_at"`
}

// New returns a new instance of the Auth service
func New(
	userSaver UserSaver,
	userProvider UserProvider,
	jwtService TokenProvider,
	config *config.Config,
	redisClient Cache,
	kafkaClient MessageBroker,
) *Auth {
	return &Auth{
		userSaver:    userSaver,
		userProvider: userProvider,
		jwtService:   jwtService,
		config:       config,
		redis:        redisClient,
		kafka:        kafkaClient,
	}
}

func (a *Auth) Login(ctx context.Context, email, password string) (string, error) {
	user, err := a.userProvider.GetUser(ctx, email)

	if err != nil {
		return "", fmt.Errorf("failed to get user: %w", err)
	}

	if err = bcrypt.CompareHashAndPassword(user.PassHash, []byte(password)); err != nil {
		return "", domain_errors.ErrInvalidCredentials
	}

	token, duration, err := a.jwtService.NewToken(user)

	if err != nil {
		return "", fmt.Errorf("failed to generate token: %w", err)
	}

	a.redis.StoreToken("token:"+token, user.ID, duration)

	return token, nil
}

func (a *Auth) ValidateToken(token string) uuid.UUID {
	return a.jwtService.ValidateToken(token)
}

func (a *Auth) Register(
	ctx context.Context,
	email string,
	username string,
	password string,
) (userId uuid.UUID, err error) {
	passHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Println("failed to generate password hash", err)
		return uuid.Nil, fmt.Errorf("failed to generate password hash")
	}

	id, err := a.userSaver.SaveUser(ctx, email, passHash)
	if err != nil {
		return uuid.Nil, fmt.Errorf("could not register new user: %w", err)
	}

	event := &UserCreatedEvent{
		UserID:   id,
		Username: username,
	}
	data, err := json.Marshal(event)
	if err != nil {
		return uuid.Nil, err
	}

	msg := kafka.Message{
		Key:   []byte(event.Username),
		Value: data,
		Time:  time.Now(),
	}

	go a.kafka.Produce(msg)

	return id, nil
}

func (a *Auth) Logout(token string) error {
	err := a.redis.RemoveToken("token:" + token)
	if err != nil {
		return fmt.Errorf("could not remove token from redis: %w", err)
	}

	return nil
}
