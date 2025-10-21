package auth

import (
	domain_errors "auth-service/internal/domain/errors"
	"context"
	"errors"
	"log"
	"net/mail"

	authService "github.com/NormVR/smap_protobuf/gen/services/auth_service"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

type Auth interface {
	Register(
		ctx context.Context,
		email string,
		password string,
	) (userId uuid.UUID, err error)
	Login(
		ctx context.Context,
		email string,
		password string,
	) (token string, err error)
	ValidateToken(
		token string,
	) (userId uuid.UUID)
	Logout(
		token string,
	) error
}

type ServerApi struct {
	authService.UnimplementedAuthServiceServer
	auth Auth
}

func Register(grpcServer *grpc.Server, auth Auth) {
	authService.RegisterAuthServiceServer(grpcServer, &ServerApi{auth: auth})
}

func (s *ServerApi) CreateUser(
	ctx context.Context,
	req *authService.CreateUserRequest,
) (*authService.CreateUserResponse, error) {
	if err := validateRegisterData(req); err != nil {
		return nil, err
	}

	userId, err := s.auth.Register(ctx, req.Email, req.Password)
	if err != nil {
		log.Printf("failed to register user: %v", err)

		switch {
		case errors.Is(err, domain_errors.ErrUserEmailExists):
			return nil, status.Errorf(codes.AlreadyExists, domain_errors.ErrUserEmailExists.Error())
		case errors.Is(err, domain_errors.ErrUserUsernameExists):
			return nil, status.Errorf(codes.AlreadyExists, domain_errors.ErrUserUsernameExists.Error())
		default:
			return nil, status.Errorf(codes.Internal, "internal server error")
		}
	}

	return &authService.CreateUserResponse{
		UserId: userId.String(),
	}, nil
}

func (s *ServerApi) Login(ctx context.Context, req *authService.LoginRequest) (*authService.LoginResponse, error) {
	err := validateLoginData(req)
	if err != nil {
		return nil, err
	}

	token, err := s.auth.Login(ctx, req.Email, req.Password)
	if err != nil {
		log.Printf("failed to login: %v", err)

		switch {
		case errors.Is(err, domain_errors.ErrInvalidCredentials):
			return nil, status.Errorf(codes.Unauthenticated, domain_errors.ErrInvalidCredentials.Error())
		case errors.Is(err, domain_errors.ErrUserNotFound):
			return nil, status.Errorf(codes.Unauthenticated, domain_errors.ErrInvalidCredentials.Error())
		default:
			return nil, status.Errorf(codes.Internal, "internal server error")
		}
	}

	return &authService.LoginResponse{
		JwtToken: token,
	}, nil
}

func (s *ServerApi) ValidateToken(ctx context.Context, req *authService.TokenRequest) (*authService.UserResponse, error) {
	if req.JwtToken == "" {
		return nil, status.Errorf(codes.InvalidArgument, "Token is empty")
	}

	userId := s.auth.ValidateToken(req.JwtToken)

	if userId == uuid.Nil {
		return nil, status.Errorf(codes.Unauthenticated, "Token is Invalid")
	}

	return &authService.UserResponse{
		UserId: userId.String(),
	}, nil
}

func (s *ServerApi) Logout(ctx context.Context, req *authService.TokenRequest) (*emptypb.Empty, error) {
	if req.JwtToken == "" {
		return nil, status.Errorf(codes.InvalidArgument, "Token is empty")
	}

	err := s.auth.Logout(req.JwtToken)

	if err != nil {
		log.Printf("failed to logout: %v", err)
		return nil, status.Error(codes.Internal, "internal server error")
	}

	return nil, nil
}

func validateRegisterData(req *authService.CreateUserRequest) error {
	if req.Email == "" {
		return status.Error(codes.InvalidArgument, "Email is required")
	}

	_, err := mail.ParseAddress(req.Email)

	if err != nil {
		return status.Error(codes.InvalidArgument, err.Error())
	}

	if req.Password == "" {
		return status.Error(codes.InvalidArgument, "Password is required")
	}

	return nil
}

func validateLoginData(req *authService.LoginRequest) error {
	if req.Password == "" {
		return status.Error(codes.InvalidArgument, "Password is required")
	}

	if req.Email == "" {
		return status.Error(codes.InvalidArgument, "Email is required")
	}

	return nil
}
