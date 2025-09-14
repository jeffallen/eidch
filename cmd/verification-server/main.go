package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/jeffallen/eiech/config"
	"github.com/jeffallen/eiech/handlers"
	"github.com/jeffallen/eiech/service"
	"github.com/jeffallen/eiech/storage"
)

func main() {
	log.Println("Starting EID-CH Verifier Agent OID4VP Go Port...")

	// Load configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Initialize storage
	db, err := storage.NewRepository(cfg)
	if err != nil {
		log.Fatalf("Failed to initialize storage: %v", err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			log.Printf("Error closing storage: %v", err)
		}
	}()

	// Initialize services
	requestObjectService := service.NewRequestObjectService(cfg, db)
	verificationService := service.NewVerificationService(cfg, db)

	// Initialize HTTP handlers
	handler := handlers.NewHandler(cfg, requestObjectService, verificationService)

	// Setup HTTP server
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	// Setup server with timeouts
	server := &http.Server{
		Addr:         fmt.Sprintf(":%s", cfg.Server.Port),
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	log.Printf("Server starting on port %s", cfg.Server.Port)
	log.Printf("Profile: %s", cfg.Profile)
	log.Printf("External URL: %s", cfg.ExternalURL)
	log.Printf("Client ID: %s", cfg.ClientID)

	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
