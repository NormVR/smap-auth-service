package auth

import (
	configProvider "auth-service/internal/config"
	domain_errors "auth-service/internal/domain/errors"
	"auth-service/internal/domain/models"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/suite"
)

type MockUserProvider struct {
	mock.Mock
}

type MockUserSaver struct {
	mock.Mock
}

type MockCache struct {
	mock.Mock
}

type MockTokenProvider struct {
	mock.Mock
}

type AuthTestSuite struct {
	suite.Suite
	ctx              context.Context
	mockUserProvider *MockUserProvider
	mockUserSaver    *MockUserSaver
	mockCache        *MockCache
	config           *configProvider.Config
	mockjwtService   *MockTokenProvider
	authService      *Auth
	expectedUser     *models.User
}

func (m *MockUserProvider) GetUser(ctx context.Context, email string) (*models.User, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}

	return args.Get(0).(*models.User), args.Error(1)
}

func (m *MockUserSaver) SaveUser(
	ctx context.Context,
	email string,
	username string,
	passHash []byte,
	firstName string,
	lastName string,
) (int64, error) {
	args := m.Called(ctx, email, username, string(passHash), firstName, lastName)

	if args.Get(0) == 0 {
		return 0, args.Error(1)
	}

	return args.Get(0).(int64), args.Error(1)
}

func (m *MockCache) StoreToken(key string, value int64, ttl time.Duration) {
	m.Called(key, value, ttl)
}

func (m *MockCache) RemoveToken(key string) error {
	args := m.Called(key)
	return args.Error(0)
}

func (m *MockTokenProvider) NewToken(user *models.User) (string, time.Duration, error) {
	args := m.Called(user)
	if args.Get(0) == nil {
		return "", 0, args.Error(2)
	}

	if args.Get(1) == 0 {
		return "", 0, args.Error(2)
	}

	return args.Get(0).(string), args.Get(1).(time.Duration), args.Error(2)
}

func (m *MockTokenProvider) ValidateToken(tokenString string) int64 {
	args := m.Called(tokenString)
	return args.Get(0).(int64)
}

func (suite *AuthTestSuite) SetupTest() {
	suite.ctx = context.Background()
	suite.mockUserProvider = new(MockUserProvider)
	suite.mockUserSaver = new(MockUserSaver)
	suite.mockCache = new(MockCache)
	suite.mockjwtService = new(MockTokenProvider)
	suite.authService = New(suite.mockUserSaver, suite.mockUserProvider, suite.mockjwtService, suite.config, suite.mockCache)

	suite.expectedUser = &models.User{
		ID:        1,
		Email:     "john_doe@test.com",
		Username:  "JDoe",
		FirstName: "John",
		LastName:  "Doe",
		PassHash:  []byte("$2a$10$GUiALc4rDfiZAqri6z8GQOzHYwQc4CTzA4EEcA98QYIW7udqqW.xO"),
	}
}

func (suite *AuthTestSuite) TearDownTest() {
	suite.mockUserProvider.AssertExpectations(suite.T())
}

func (suite *AuthTestSuite) TestAuth_Login_Success() {
	suite.mockUserProvider.On("GetUser", suite.ctx, suite.expectedUser.Email).Return(suite.expectedUser, nil)
	suite.mockCache.On("StoreToken", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	suite.mockjwtService.On("NewToken", suite.expectedUser).Return("token", time.Duration(24)*time.Hour, nil)

	token, err := suite.authService.Login(suite.ctx, "john_doe@test.com", "password")

	suite.NoError(err)
	suite.NotNil(token)
	suite.NotEmpty(token)
	suite.mockUserSaver.AssertExpectations(suite.T())
	suite.mockCache.AssertExpectations(suite.T())
	suite.mockjwtService.AssertExpectations(suite.T())
}

func (suite *AuthTestSuite) TestAuth_Login_InvalidPassword() {
	suite.mockUserProvider.On("GetUser", suite.ctx, suite.expectedUser.Email).Return(suite.expectedUser, nil)

	token, err := suite.authService.Login(suite.ctx, "john_doe@test.com", "wrong_password")

	suite.Error(err)
	suite.ErrorIs(err, domain_errors.ErrInvalidCredentials)
	suite.Empty(token)
	suite.mockUserSaver.AssertNotCalled(suite.T(), "SaveUser")
}

func (suite *AuthTestSuite) TestAuth_Login_UserNotFound() {
	suite.mockUserProvider.On("GetUser", suite.ctx, "wrong_user@test.com").Return(nil, domain_errors.ErrUserNotFound)

	token, err := suite.authService.Login(suite.ctx, "wrong_user@test.com", "password")

	suite.Error(err)
	suite.Empty(token)
	suite.mockUserSaver.AssertNotCalled(suite.T(), "SaveUser")
}

func (suite *AuthTestSuite) TestAuth_Login_TokenError() {
	suite.mockUserProvider.On("GetUser", suite.ctx, suite.expectedUser.Email).Return(suite.expectedUser, nil)
	suite.mockCache.On("StoreToken", mock.Anything, mock.Anything, mock.Anything).Return(nil)
	suite.mockjwtService.On("NewToken", suite.expectedUser).Return("", 0, errors.New("some error"))

	token, err := suite.authService.Login(suite.ctx, "john_doe@test.com", "password")

	suite.Error(err)
	suite.Empty(token)
	suite.mockUserSaver.AssertExpectations(suite.T())
	suite.mockjwtService.AssertExpectations(suite.T())
	suite.mockCache.AssertNotCalled(suite.T(), "StoreToken")
}

func (suite *AuthTestSuite) TestAuth_Login_TokenValid() {
	suite.mockjwtService.On("ValidateToken", mock.Anything).Return(suite.expectedUser.ID)
	uid := suite.authService.ValidateToken("test")

	suite.NotNil(uid)
	suite.IsType(int64(0), uid)
}

func (suite *AuthTestSuite) TestAuth_Login_RegisterSuccess() {
	suite.mockUserSaver.On(
		"SaveUser",
		suite.ctx,
		suite.expectedUser.Email,
		suite.expectedUser.Username,
		mock.Anything,
		suite.expectedUser.FirstName,
		suite.expectedUser.LastName).Return(suite.expectedUser.ID, nil)

	uid, err := suite.authService.Register(
		suite.ctx,
		suite.expectedUser.Email,
		suite.expectedUser.Username,
		"password",
		suite.expectedUser.FirstName,
		suite.expectedUser.LastName,
	)
	suite.NoError(err)
	suite.NotNil(uid)
	suite.NotEmpty(uid)
}

func (suite *AuthTestSuite) TestAuth_Login_SaveUserError() {
	suite.mockUserSaver.On(
		"SaveUser",
		mock.Anything,
		mock.Anything,
		mock.Anything,
		mock.Anything,
		mock.Anything,
		mock.Anything).Return(0, errors.New("some error"))

	uid, err := suite.authService.Register(
		suite.ctx,
		suite.expectedUser.Email,
		suite.expectedUser.Username,
		"password",
		suite.expectedUser.FirstName,
		suite.expectedUser.LastName,
	)

	suite.Error(err)
	suite.Equal(int64(0), uid)
}

func (suite *AuthTestSuite) TestAuth_Login_LogoutSuccess() {
	suite.mockCache.On("RemoveToken", mock.Anything).Return(nil)

	err := suite.authService.Logout("token")
	suite.NoError(err)
}

func (suite *AuthTestSuite) TestAuth_Login_LogoutFail() {
	suite.mockCache.On("RemoveToken", mock.Anything).Return(errors.New("some error"))

	err := suite.authService.Logout("token")
	suite.Error(err)
}

func TestAuthTestSuite(t *testing.T) {
	suite.Run(t, new(AuthTestSuite))
}
