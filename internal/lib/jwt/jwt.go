package jwt

import (
	"auth-service/internal/domain/models"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type JwtService struct {
	secret   []byte
	duration time.Duration
}

func NewJwtService(secret []byte, duration time.Duration) *JwtService {
	return &JwtService{
		secret:   secret,
		duration: duration,
	}
}

func (j *JwtService) NewToken(user *models.User) (string, time.Duration, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"uid":   user.ID,
		"email": user.Email,
		"exp":   time.Now().Add(j.duration).Unix(),
	})

	tokenString, err := token.SignedString(j.secret)

	if err != nil {
		return "", 0, err
	}

	return tokenString, j.duration, nil
}

func (j *JwtService) ValidateToken(tokenString string) uuid.UUID {

	tokenString = strings.TrimSpace(tokenString)

	claims := &jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return j.secret, nil
	})

	if err != nil || !token.Valid {
		log.Println(err)
		return uuid.Nil
	}
	uid := (*claims)["uid"]
	id, err := uuid.Parse(uid.(string))
	if err != nil {
		log.Println(err)
		return uuid.Nil
	}
	return id
}
