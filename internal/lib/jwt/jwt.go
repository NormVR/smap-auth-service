package jwt

import (
	"auth-service/internal/domain/models"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
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

func (j *JwtService) NewToken(user *models.User) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"uid":   user.ID,
		"email": user.Email,
		"exp":   time.Now().Add(j.duration).Unix(),
	})

	tokenString, err := token.SignedString([]byte(j.secret))

	if err != nil {
		return "", err
	}

	return tokenString, nil
}

func (j *JwtService) ValidateToken(tokenString string) int64 {

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
		return 0
	}
	uid := (*claims)["uid"]

	return int64(uid.(float64))
}
