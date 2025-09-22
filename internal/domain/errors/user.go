package errors

import (
	"errors"
)

var (
	ErrUserNotFound       = errors.New("user not found")
	ErrUserEmailExists    = errors.New("user with this email already exists")
	ErrUserUsernameExists = errors.New("user with this username already exists")
	ErrInvalidCredentials = errors.New("invalid login or password")
)
