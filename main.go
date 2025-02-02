package main

import (
	"log"
	"openport-exporter/app"
)

func main() {
	application, err := app.NewApp("config.yaml", nil)
	if err != nil {
		log.Fatalf("Failed to initialize application: %v", err)
	}

	if err := application.Run(); err != nil {
		log.Fatalf("Application failed: %v", err)
	}
}
