package issuer

import (
	"fmt"
	"log"
	"net/http"
	"time"
)

// Server represents the issuer server
type Server struct {
	config   *Config
	handlers *Handlers
	server   *http.Server
}

// GetHandlers returns the server handlers (for testing)
func (s *Server) GetHandlers() *Handlers {
	return s.handlers
}

// NewServer creates a new issuer server instance
func NewServer(cfg *Config) (*Server, error) {
	// Initialize storage
	store, err := NewStorage(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize storage: %w", err)
	}

	// Initialize services
	credentialService := NewCredentialService(cfg, store)
	nonceService := NewNonceService(cfg)
	managementService := NewManagementService(cfg, store)

	// Initialize handlers
	handlers := NewHandlers(cfg, credentialService, nonceService, managementService)

	// Setup HTTP server
	mux := http.NewServeMux()
	handlers.RegisterRoutes(mux)

	server := &http.Server{
		Addr:         fmt.Sprintf(":%s", cfg.Server.Port),
		Handler:      mux,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	return &Server{
		config:   cfg,
		handlers: handlers,
		server:   server,
	}, nil
}

// Start starts the server
func (s *Server) Start() error {
	log.Printf("Starting issuer server on %s", s.server.Addr)
	return s.server.ListenAndServe()
}

// Stop stops the server gracefully
func (s *Server) Stop() error {
	return s.server.Close()
}
