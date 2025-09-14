package handlers

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"

	"github.com/jeffallen/eiech/config"
	"github.com/jeffallen/eiech/domain"
	"github.com/jeffallen/eiech/service"
)

// Handler contains all HTTP handlers
type Handler struct {
	config               *config.Config
	requestObjectService *service.RequestObjectService
	verificationService  *service.VerificationService
}

// NewHandler creates a new Handler instance
func NewHandler(cfg *config.Config, reqObjService *service.RequestObjectService, verService *service.VerificationService) *Handler {
	return &Handler{
		config:               cfg,
		requestObjectService: reqObjService,
		verificationService:  verService,
	}
}

// RegisterRoutes registers all HTTP routes
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	// OpenID4VP endpoints
	mux.HandleFunc("/api/v1/openid-client-metadata.json", h.getOpenIdClientMetadata)
	mux.HandleFunc("/api/v1/request-object/", h.handleRequestObjectRoutes)

	// Health check endpoint
	mux.HandleFunc("/health", h.healthCheck)

	// Add CORS middleware wrapper
	mux.HandleFunc("/", h.corsMiddleware(mux.ServeHTTP))
}

// corsMiddleware adds CORS headers
func (h *Handler) corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next(w, r)
	}
}

// getOpenIdClientMetadata handles GET /api/v1/openid-client-metadata.json
func (h *Handler) getOpenIdClientMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(h.config.Client.Metadata); err != nil {
		log.Printf("Error encoding client metadata: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// handleRequestObjectRoutes handles all request object related routes
func (h *Handler) handleRequestObjectRoutes(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	parts := strings.Split(strings.TrimPrefix(path, "/api/v1/request-object/"), "/")

	if len(parts) < 1 || parts[0] == "" {
		http.Error(w, "Invalid request object path", http.StatusBadRequest)
		return
	}

	requestID := parts[0]

	// Handle different sub-paths
	if len(parts) == 1 {
		// GET /api/v1/request-object/{request_id}
		if r.Method == http.MethodGet {
			h.getRequestObject(w, r, requestID)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	} else if len(parts) == 2 && parts[1] == "response-data" {
		// POST /api/v1/request-object/{request_id}/response-data
		if r.Method == http.MethodPost {
			h.receiveVerificationPresentation(w, r, requestID)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	} else {
		http.Error(w, "Not found", http.StatusNotFound)
	}
}

// getRequestObject handles GET /api/v1/request-object/{request_id}
func (h *Handler) getRequestObject(w http.ResponseWriter, r *http.Request, requestID string) {
	log.Printf("Getting request object for ID: %s", requestID)

	requestObject, err := h.requestObjectService.AssembleRequestObject(requestID)
	if err != nil {
		h.handleVerificationError(w, err)
		return
	}

	// Check if it's a signed JWT string or a request object
	if jwtString, ok := requestObject.(string); ok {
		// Return as JWT string
		w.Header().Set("Content-Type", "application/jwt")
		w.Write([]byte(jwtString))
	} else {
		// Return as JSON
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(requestObject); err != nil {
			log.Printf("Error encoding request object: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
	}
}

// receiveVerificationPresentation handles POST /api/v1/request-object/{request_id}/response-data
func (h *Handler) receiveVerificationPresentation(w http.ResponseWriter, r *http.Request, requestID string) {
	log.Printf("Receiving verification presentation for ID: %s", requestID)

	// Parse form data
	if err := r.ParseForm(); err != nil {
		log.Printf("Error parsing form data: %v", err)
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	// Extract verification presentation request from form
	request := &domain.VerificationPresentationRequest{
		VPToken:                r.FormValue("vp_token"),
		PresentationSubmission: r.FormValue("presentation_submission"),
		Error:                  r.FormValue("error"),
		ErrorDescription:       r.FormValue("error_description"),
	}

	log.Printf("Parsed verification request: vp_token=%t, presentation_submission=%t, error=%s",
		len(request.VPToken) > 0, len(request.PresentationSubmission) > 0, request.Error)

	// Process the verification
	if err := h.verificationService.ReceiveVerificationPresentation(requestID, request); err != nil {
		h.handleVerificationError(w, err)
		return
	}

	// Success response
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Verification presentation received successfully"))
}

// healthCheck handles GET /health
func (h *Handler) healthCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "healthy",
		"service": "github.com/jeffallen/eiech",
	})
}

// handleVerificationError handles verification errors and returns appropriate HTTP responses
func (h *Handler) handleVerificationError(w http.ResponseWriter, err error) {
	if verErr, ok := err.(*service.VerificationError); ok {
		// Map verification error types to HTTP status codes
		statusCode := http.StatusBadRequest
		switch verErr.Type {
		case domain.VerificationErrorAuthorizationRequestObjectNotFound:
			statusCode = http.StatusNotFound
		case domain.VerificationErrorVerificationProcessClosed:
			statusCode = http.StatusGone
		}

		// Create error response
		errorResponse := map[string]interface{}{
			"error":             string(verErr.Type),
			"error_code":        string(verErr.Code),
			"error_description": verErr.Message,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		json.NewEncoder(w).Encode(errorResponse)
		return
	}

	// Generic error
	log.Printf("Internal error: %v", err)
	http.Error(w, "Internal server error", http.StatusInternalServerError)
}

// parseRequestID extracts request ID from URL path
func parseRequestID(path string) (string, error) {
	parts := strings.Split(path, "/")
	for i, part := range parts {
		if part == "request-object" && i+1 < len(parts) {
			requestID := parts[i+1]
			if requestID == "" {
				return "", fmt.Errorf("empty request ID")
			}
			return requestID, nil
		}
	}
	return "", fmt.Errorf("request ID not found in path")
}

// parseURLEncoded parses URL encoded form data
func parseURLEncoded(body string) (url.Values, error) {
	return url.ParseQuery(body)
}
