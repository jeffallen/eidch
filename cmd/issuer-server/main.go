package main

import (
	"eidch-verifier-agent-oid4vp-go/issuer"
	"log"
)

func main() {
	log.Println("Starting EID-CH Issuer Server...")

	// Get configuration from environment/args
	cfg, err := issuer.LoadConfigFromEnv()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Create and start server
	server, err := issuer.NewServer(cfg)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	log.Printf("Server starting on port %s", cfg.Server.Port)
	log.Printf("External URL: %s", cfg.ExternalURL)
	log.Printf("Issuer ID: %s", cfg.IssuerID)

	if err := server.Start(); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
