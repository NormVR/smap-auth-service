package main

import (
	"auth-service/internal/app"
	"auth-service/internal/config"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	configData, err := config.LoadConfig()

	if err != nil {
		log.Fatal("Failed to load config:", err)
	}

	application := app.New(configData)
	go application.GrpcSrv.MustRun()
	stop := make(chan os.Signal, 1)
	sign := <-stop
	log.Println("Stopping by signal ", sign)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)
	application.GrpcSrv.Stop()
}
