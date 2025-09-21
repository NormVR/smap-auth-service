package auth

import (
	"context"
	"net/mail"

	userservice "github.com/NormVR/smap_protobuf/gen"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Auth interface {
	Register(
		ctx context.Context,
		email string,
		username string,
		password string,
		firstName string,
		lastName string,
	) (userId int64, err error)
	Login(
		ctx context.Context,
		email string,
		password string,
	) (token string, err error)
}

type ServerApi struct {
	userservice.UnimplementedAuthServiceServer
	auth Auth
}

func Register(grpcServer *grpc.Server, auth Auth) {
	userservice.RegisterAuthServiceServer(grpcServer, &ServerApi{auth: auth})
}

func (s *ServerApi) CreateUser(
	ctx context.Context,
	req *userservice.CreateUserRequest,
) (*userservice.CreateUserResponse, error) {
	if err := validateRegisterData(req); err != nil {
		return nil, err
	}

	userId, err := s.auth.Register(ctx, req.Email, req.Username, req.Password, req.FirstName, req.LastName)
	if err != nil {
		return nil, err
	}

	return &userservice.CreateUserResponse{
		UserId: userId,
	}, nil
}

func (s *ServerApi) Login(ctx context.Context, req *userservice.LoginRequest) (*userservice.LoginResponse, error) {
	err := validateLoginData(req)
	if err != nil {
		return nil, err
	}

	token, err := s.auth.Login(ctx, req.Email, req.Password)
	if err != nil {
		return nil, err
	}

	return &userservice.LoginResponse{
		JwtToken: token,
	}, nil
}

func validateRegisterData(req *userservice.CreateUserRequest) error {
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

	if req.FirstName == "" || req.LastName == "" {
		return status.Error(codes.InvalidArgument, "First name and Last name are required")
	}

	return nil
}

func validateLoginData(req *userservice.LoginRequest) error {
	if req.Password == "" {
		return status.Error(codes.InvalidArgument, "Password is required")
	}

	if req.Email == "" {
		return status.Error(codes.InvalidArgument, "Email is required")
	}

	return nil
}
