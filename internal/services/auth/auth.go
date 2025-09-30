package auth

import (
	"auth-service/internal/config"
	domain_errors "auth-service/internal/domain/errors"
	"auth-service/internal/domain/models"
	"context"
	"fmt"
	"log"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type Auth struct {
	userSaver    UserSaver
	userProvider UserProvider
	jwtService   TokenProvider
	config       *config.Config
	redis        Cache
}

type UserSaver interface {
	SaveUser(
		ctx context.Context,
		email string,
		username string,
		passHash []byte,
		firstName string,
		lastName string,
	) (int64, error)
}

type UserProvider interface {
	GetUser(ctx context.Context, email string) (*models.User, error)
}

type Cache interface {
	StoreToken(key string, value int64, ttl time.Duration)
	RemoveToken(key string) error
}

type TokenProvider interface {
	NewToken(user *models.User) (string, time.Duration, error)
	ValidateToken(tokenString string) int64
}

// New returns a new instance of the Auth service
func New(
	userSaver UserSaver,
	userProvider UserProvider,
	jwtService TokenProvider,
	config *config.Config,
	redisClient Cache,
) *Auth {
	return &Auth{
		userSaver:    userSaver,
		userProvider: userProvider,
		jwtService:   jwtService,
		config:       config,
		redis:        redisClient,
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

func (a *Auth) ValidateToken(token string) int64 {
	return a.jwtService.ValidateToken(token)
}

func (a *Auth) Register(
	ctx context.Context,
	email string,
	username string,
	password string,
	firstName string,
	lastName string,
) (userId int64, err error) {
	passHash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Println("failed to generate password hash", err)
		return 0, fmt.Errorf("failed to generate password hash")
	}

	id, err := a.userSaver.SaveUser(ctx, email, username, passHash, firstName, lastName)
	if err != nil {
		return 0, fmt.Errorf("could not register new user: %w", err)
	}

	return id, nil
}

func (a *Auth) Logout(token string) error {
	err := a.redis.RemoveToken("token:" + token)
	if err != nil {
		return fmt.Errorf("could not remove token from redis: %w", err)
	}

	return nil
}
