package grpcapp

import (
	authGrpc "auth-service/internal/grpc/auth"
	"fmt"
	"log"
	"net"

	"google.golang.org/grpc"
)

type App struct {
	grpcServer *grpc.Server
	port       int
}

func New(authService authGrpc.Auth, port int) *App {
	grpcServer := grpc.NewServer()
	authGrpc.Register(grpcServer, authService)
	return &App{
		grpcServer: grpcServer,
		port:       port,
	}
}

func (app *App) MustRun() {
	if err := app.Run(); err != nil {
		panic(err)
	}
}

func (a *App) Run() error {
	l, err := net.Listen("tcp", fmt.Sprintf(":%d", a.port))
	if err != nil {
		return err
	}

	log.Println("gRPC server running on", l.Addr())

	if err = a.grpcServer.Serve(l); err != nil {
		return err
	}

	return nil
}

func (a *App) Stop() {
	log.Println("gRPC server shutting down")
	a.grpcServer.GracefulStop()
}
