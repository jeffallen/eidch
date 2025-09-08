package issuer

import (
	"encoding/json"
	"log"
	"net/http"
	"regexp"
	"strings"
)

// Handlers contains all HTTP handlers
type Handlers struct {
	config            *Config
	credentialService *CredentialService
	nonceService      *NonceService
	managementService *ManagementService
}

// NewHandlers creates a new Handlers instance
func NewHandlers(cfg *Config, credSvc *CredentialService, nonceSvc *NonceService, mgmtSvc *ManagementService) *Handlers {
	return &Handlers{
		config:            cfg,
		credentialService: credSvc,
		nonceService:      nonceSvc,
		managementService: mgmtSvc,
	}
}

// RegisterRoutes registers all HTTP routes
func (h *Handlers) RegisterRoutes(mux *http.ServeMux) {
	// Well-known endpoints
	mux.HandleFunc("/.well-known/openid-configuration", h.getOpenIDConfiguration)
	mux.HandleFunc("/.well-known/oauth-authorization-server", h.getOAuthAuthorizationServer)
	mux.HandleFunc("/.well-known/openid-credential-issuer", h.getIssuerMetadata)

	// OID4VCI API endpoints
	mux.HandleFunc("/oid4vci/api/token", h.handleToken)
	mux.HandleFunc("/oid4vci/api/nonce", h.handleNonce)
	mux.HandleFunc("/oid4vci/api/credential", h.handleCredential)
	mux.HandleFunc("/oid4vci/api/deferred_credential", h.handleDeferredCredential)

	// Management API endpoints
	mux.HandleFunc("/management/api/credentials", h.handleCredentialManagement)
	mux.HandleFunc("/management/api/credentials/", h.handleCredentialOfferOperations)

	// Credential offer endpoint
	mux.HandleFunc("/credential-offer", h.handleCredentialOffer)

	// Health check
	mux.HandleFunc("/health", h.healthCheck)

	// Add CORS middleware
	mux.HandleFunc("/", h.corsMiddleware(mux.ServeHTTP))
}

// corsMiddleware adds CORS headers
func (h *Handlers) corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, SWIYU-API-Version")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next(w, r)
	}
}

// getOpenIDConfiguration handles GET /.well-known/openid-configuration
func (h *Handlers) getOpenIDConfiguration(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	config := &OpenIDConfiguration{
		Issuer:                            h.config.ExternalURL,
		TokenEndpoint:                     h.config.ExternalURL + "/oid4vci/api/token",
		GrantTypesSupported:               []string{"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
		TokenEndpointAuthMethodsSupported: []string{"none"},
		SubjectTypesSupported:             []string{"public"},
		IDTokenSigningAlgValuesSupported:  []string{"ES256"},
		ResponseTypesSupported:            []string{"code"},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(config)
}

// getOAuthAuthorizationServer handles GET /.well-known/oauth-authorization-server
func (h *Handlers) getOAuthAuthorizationServer(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	config := &OAuthAuthorizationServerMetadata{
		Issuer:                            h.config.ExternalURL,
		TokenEndpoint:                     h.config.ExternalURL + "/oid4vci/api/token",
		GrantTypesSupported:               []string{"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
		TokenEndpointAuthMethodsSupported: []string{"none"},
		TokenEndpointAuthSigningAlgValuesSupported: []string{"ES256"},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(config)
}

// getIssuerMetadata handles GET /.well-known/openid-credential-issuer
func (h *Handlers) getIssuerMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	metadata := &IssuerMetadata{
		CredentialIssuer:           h.config.ExternalURL,
		CredentialEndpoint:         h.config.ExternalURL + "/oid4vci/api/credential",
		DeferredCredentialEndpoint: h.config.ExternalURL + "/oid4vci/api/deferred_credential",
		CredentialsSupported:       h.config.Metadata.CredentialsSupported,
		Display:                    []DisplayInfo{h.config.Metadata.DisplayInfo},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(metadata)
}

// handleToken handles POST /oid4vci/api/token
func (h *Handlers) handleToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var tokenReq TokenRequest

	// Handle both form-encoded and query parameters
	contentType := r.Header.Get("Content-Type")
	if strings.Contains(contentType, "application/x-www-form-urlencoded") {
		if err := r.ParseForm(); err != nil {
			h.writeOAuthError(w, "invalid_request", "Failed to parse form data")
			return
		}
		tokenReq.GrantType = r.FormValue("grant_type")
		tokenReq.PreAuthorizedCode = r.FormValue("pre-authorized_code")
	} else {
		// Handle query parameters for backward compatibility
		tokenReq.GrantType = r.URL.Query().Get("grant_type")
		tokenReq.PreAuthorizedCode = r.URL.Query().Get("pre-authorized_code")
	}

	// Validate grant type
	if tokenReq.GrantType != "urn:ietf:params:oauth:grant-type:pre-authorized_code" {
		h.writeOAuthError(w, "invalid_request", "Invalid grant type")
		return
	}

	// Validate pre-authorized code
	if strings.TrimSpace(tokenReq.PreAuthorizedCode) == "" {
		h.writeOAuthError(w, "invalid_request", "Pre-authorized code is required")
		return
	}

	// Issue token
	tokenResp, err := h.credentialService.IssueOAuthToken(tokenReq.PreAuthorizedCode)
	if err != nil {
		if oauthErr, ok := err.(*OAuthError); ok {
			h.writeOAuthError(w, oauthErr.ErrorType, oauthErr.ErrorDescription)
			return
		}
		log.Printf("Error issuing token: %v", err)
		h.writeOAuthError(w, "server_error", "Internal server error")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tokenResp)
}

// handleNonce handles POST /oid4vci/api/nonce
func (h *Handlers) handleNonce(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	nonce, err := h.nonceService.CreateNonce()
	if err != nil {
		log.Printf("Error creating nonce: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Set no-cache headers for nonce endpoint
	w.Header().Set("Cache-Control", "no-cache, no-store, max-age=0, must-revalidate")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(nonce)
}

// handleCredential handles POST /oid4vci/api/credential
func (h *Handlers) handleCredential(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Extract access token
	accessToken := h.extractAccessToken(r)
	if accessToken == "" {
		h.writeCredentialError(w, "invalid_token", "No access token provided")
		return
	}

	// Parse request body
	var credReq CredentialRequest
	if err := json.NewDecoder(r.Body).Decode(&credReq); err != nil {
		h.writeCredentialError(w, "invalid_request", "Invalid request body")
		return
	}

	// Get client agent info
	clientInfo := &ClientAgentInfo{
		RemoteAddr:     r.RemoteAddr,
		UserAgent:      r.Header.Get("User-Agent"),
		AcceptLanguage: r.Header.Get("Accept-Language"),
		AcceptEncoding: r.Header.Get("Accept-Encoding"),
	}

	// Issue credential
	credResp, err := h.credentialService.IssueCredential(accessToken, &credReq, clientInfo)
	if err != nil {
		if credErr, ok := err.(*CredentialError); ok {
			h.writeCredentialError(w, credErr.ErrorType, credErr.ErrorDescription)
			return
		}
		log.Printf("Error issuing credential: %v", err)
		h.writeCredentialError(w, "server_error", "Internal server error")
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(credResp)
}

// handleDeferredCredential handles POST /oid4vci/api/deferred_credential
func (h *Handlers) handleDeferredCredential(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// For simplicity, deferred credentials are not implemented in this demo
	h.writeCredentialError(w, "unsupported_credential_type", "Deferred credentials not supported")
}

// handleCredentialManagement handles credential management operations
func (h *Handlers) handleCredentialManagement(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		h.createCredentialOffer(w, r)
	case http.MethodGet:
		h.listCredentialOffers(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleCredentialOfferOperations handles operations on specific credential offers
func (h *Handlers) handleCredentialOfferOperations(w http.ResponseWriter, r *http.Request) {
	// Extract offer ID from path
	path := strings.TrimPrefix(r.URL.Path, "/management/api/credentials/")
	parts := strings.Split(path, "/")
	if len(parts) == 0 || parts[0] == "" {
		http.Error(w, "Offer ID required", http.StatusBadRequest)
		return
	}

	offerID := parts[0]

	switch r.Method {
	case http.MethodGet:
		h.getCredentialOffer(w, r, offerID)
	case http.MethodPut:
		if len(parts) > 1 && parts[1] == "status" {
			h.updateCredentialOfferStatus(w, r, offerID)
		} else {
			http.Error(w, "Invalid operation", http.StatusBadRequest)
		}
	case http.MethodDelete:
		h.deleteCredentialOffer(w, r, offerID)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// createCredentialOffer handles POST /management/api/credentials
func (h *Handlers) createCredentialOffer(w http.ResponseWriter, r *http.Request) {
	var request CredentialOfferRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate required fields
	if request.CredentialType == "" {
		http.Error(w, "Credential type is required", http.StatusBadRequest)
		return
	}

	if request.CredentialData == nil {
		http.Error(w, "Credential data is required", http.StatusBadRequest)
		return
	}

	response, err := h.managementService.CreateCredentialOffer(&request)
	if err != nil {
		log.Printf("Error creating credential offer: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}

// getCredentialOffer handles GET /management/api/credentials/{id}
func (h *Handlers) getCredentialOffer(w http.ResponseWriter, r *http.Request, offerID string) {
	offer, err := h.managementService.GetCredentialOffer(offerID)
	if err != nil {
		log.Printf("Error getting credential offer: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if offer == nil {
		http.Error(w, "Credential offer not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(offer)
}

// updateCredentialOfferStatus handles PUT /management/api/credentials/{id}/status
func (h *Handlers) updateCredentialOfferStatus(w http.ResponseWriter, r *http.Request, offerID string) {
	var statusReq struct {
		Status CredentialOfferStatus `json:"status"`
	}

	if err := json.NewDecoder(r.Body).Decode(&statusReq); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if err := h.managementService.UpdateCredentialOfferStatus(offerID, statusReq.Status); err != nil {
		log.Printf("Error updating credential offer status: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// deleteCredentialOffer handles DELETE /management/api/credentials/{id}
func (h *Handlers) deleteCredentialOffer(w http.ResponseWriter, r *http.Request, offerID string) {
	// Implementation depends on requirements - for now, just return 501
	http.Error(w, "Not implemented", http.StatusNotImplemented)
}

// listCredentialOffers handles GET /management/api/credentials
func (h *Handlers) listCredentialOffers(w http.ResponseWriter, r *http.Request) {
	// Implementation depends on requirements - for now, just return 501
	http.Error(w, "Not implemented", http.StatusNotImplemented)
}

// handleCredentialOffer handles GET /credential-offer
func (h *Handlers) handleCredentialOffer(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	offerID := r.URL.Query().Get("offer_id")
	if offerID == "" {
		http.Error(w, "Offer ID required", http.StatusBadRequest)
		return
	}

	offer, err := h.managementService.GetCredentialOffer(offerID)
	if err != nil {
		log.Printf("Error getting credential offer: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if offer == nil {
		http.Error(w, "Credential offer not found", http.StatusNotFound)
		return
	}

	// Return credential offer in OID4VCI format
	offerResponse := map[string]interface{}{
		"credential_issuer": h.config.ExternalURL,
		"credentials":       []string{offer.CredentialType},
		"grants": map[string]interface{}{
			"urn:ietf:params:oauth:grant-type:pre-authorized_code": map[string]interface{}{
				"pre-authorized_code": offer.PreAuthorizedCode,
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(offerResponse)
}

// healthCheck handles GET /health
func (h *Handlers) healthCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "healthy",
		"service": "eidch-issuer-go",
	})
}

// Helper functions

func (h *Handlers) extractAccessToken(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return ""
	}

	regex := regexp.MustCompile(`(?i)bearer\s+(.+)`)
	matches := regex.FindStringSubmatch(authHeader)
	if len(matches) < 2 {
		return ""
	}

	return matches[1]
}

func (h *Handlers) writeOAuthError(w http.ResponseWriter, errorCode, description string) {
	errorResp := &OAuthError{
		ErrorType:        errorCode,
		ErrorDescription: description,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(w).Encode(errorResp)
}

func (h *Handlers) writeCredentialError(w http.ResponseWriter, errorCode, description string) {
	errorResp := &CredentialError{
		ErrorType:        errorCode,
		ErrorDescription: description,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(w).Encode(errorResp)
}
