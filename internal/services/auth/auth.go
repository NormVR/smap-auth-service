package auth

import (
	domain_errors "auth-service/internal/domain/errors"
	"auth-service/internal/domain/models"
	"auth-service/internal/lib/jwt"
	"context"
	"fmt"
	"log"

	"golang.org/x/crypto/bcrypt"
)

type Auth struct {
	userSaver    UserSaver
	userProvider UserProvider
	jwtService   *jwt.JwtService
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

// New returns a new instance of the Auth service
func New(
	userSaver UserSaver,
	userProvider UserProvider,
	jwtService *jwt.JwtService,
) *Auth {
	return &Auth{
		userSaver:    userSaver,
		userProvider: userProvider,
		jwtService:   jwtService,
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

	token, err := a.jwtService.NewToken(user)

	if err != nil {
		return "", fmt.Errorf("failed to generate token: %w", err)
	}

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
