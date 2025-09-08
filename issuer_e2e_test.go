package main

import (
	"bytes"
	"eidch-verifier-agent-oid4vp-go/issuer"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestIssuerEndToEndFlow tests the complete issuer flow similar to the Java IssuanceControllerIT
func TestIssuerEndToEndFlow(t *testing.T) {
	// Create test HTTP server
	httpServer := httptest.NewServer(createIssuerMux("")) // Empty URL will be replaced
	defer httpServer.Close()

	// Update the mux with the correct server URL
	httpServer.Config.Handler = createIssuerMux(httpServer.URL)

	// Test Step 1: Get well-known configurations
	t.Run("GetWellKnownConfigurations", func(t *testing.T) {
		// Test OpenID configuration
		resp, err := http.Get(httpServer.URL + "/.well-known/openid-configuration")
		if err != nil {
			t.Fatalf("Failed to get OpenID configuration: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Expected status 200, got %d", resp.StatusCode)
		}

		var config map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
			t.Fatalf("Failed to decode OpenID configuration: %v", err)
		}

		if !strings.Contains(config["token_endpoint"].(string), "/oid4vci/api/token") {
			t.Fatal("Expected token_endpoint in OpenID configuration")
		}

		// Test OAuth authorization server metadata
		resp, err = http.Get(httpServer.URL + "/.well-known/oauth-authorization-server")
		if err != nil {
			t.Fatalf("Failed to get OAuth authorization server metadata: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Expected status 200, got %d", resp.StatusCode)
		}

		// Test issuer metadata
		resp, err = http.Get(httpServer.URL + "/.well-known/openid-credential-issuer")
		if err != nil {
			t.Fatalf("Failed to get issuer metadata: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Expected status 200, got %d", resp.StatusCode)
		}

		var issuerMetadata map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&issuerMetadata); err != nil {
			t.Fatalf("Failed to decode issuer metadata: %v", err)
		}

		if !strings.Contains(issuerMetadata["credential_endpoint"].(string), "/oid4vci/api/credential") {
			t.Fatal("Expected credential_endpoint in issuer metadata")
		}
	})

	// Test Step 2: Create credential offer via management API
	var credentialOffer *issuer.CredentialOfferResponse
	t.Run("CreateCredentialOffer", func(t *testing.T) {
		offerRequest := &issuer.CredentialOfferRequest{
			CredentialType: "example_sd_jwt",
			CredentialData: map[string]interface{}{
				"given_name":  "John",
				"family_name": "Doe",
				"email":       "john.doe@example.com",
			},
			ValidityPeriodDays: intPtr(30),
		}

		reqBody, _ := json.Marshal(offerRequest)
		resp, err := http.Post(
			httpServer.URL+"/management/api/credentials",
			"application/json",
			bytes.NewReader(reqBody),
		)
		if err != nil {
			t.Fatalf("Failed to create credential offer: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusCreated {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("Expected status 201, got %d. Body: %s", resp.StatusCode, string(body))
		}

		if err := json.NewDecoder(resp.Body).Decode(&credentialOffer); err != nil {
			t.Fatalf("Failed to decode credential offer response: %v", err)
		}

		if credentialOffer.OfferID == "" {
			t.Fatal("Expected non-empty offer ID")
		}

		if credentialOffer.DeepLink == "" {
			t.Fatal("Expected non-empty deep link")
		}
	})

	// Test Step 3: Get credential offer details
	t.Run("GetCredentialOfferDetails", func(t *testing.T) {
		resp, err := http.Get(credentialOffer.CredentialOfferURI)
		if err != nil {
			t.Fatalf("Failed to get credential offer details: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Expected status 200, got %d", resp.StatusCode)
		}

		var offerDetails map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&offerDetails); err != nil {
			t.Fatalf("Failed to decode offer details: %v", err)
		}

		if offerDetails["credential_issuer"] == nil {
			t.Fatal("Expected credential_issuer in offer details")
		}

		grants, ok := offerDetails["grants"].(map[string]interface{})
		if !ok {
			t.Fatal("Expected grants in offer details")
		}

		preAuthGrant, ok := grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"].(map[string]interface{})
		if !ok {
			t.Fatal("Expected pre-authorized code grant in offer details")
		}

		if preAuthGrant["pre-authorized_code"] == nil {
			t.Fatal("Expected pre-authorized_code in grant details")
		}
	})

	// Extract pre-authorized code from the credential offer
	var preAuthCode string
	t.Run("ExtractPreAuthCode", func(t *testing.T) {
		resp, err := http.Get(credentialOffer.CredentialOfferURI)
		if err != nil {
			t.Fatalf("Failed to get credential offer: %v", err)
		}
		defer resp.Body.Close()

		var offerDetails map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&offerDetails)

		grants := offerDetails["grants"].(map[string]interface{})
		preAuthGrant := grants["urn:ietf:params:oauth:grant-type:pre-authorized_code"].(map[string]interface{})
		preAuthCode = preAuthGrant["pre-authorized_code"].(string)

		if preAuthCode == "" {
			t.Fatal("Failed to extract pre-authorized code")
		}
	})

	// Test Step 4: Exchange pre-authorized code for access token
	var accessToken string
	t.Run("ExchangeTokenWithFormData", func(t *testing.T) {
		formData := url.Values{
			"grant_type":          {"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
			"pre-authorized_code": {preAuthCode},
		}

		resp, err := http.PostForm(httpServer.URL+"/oid4vci/api/token", formData)
		if err != nil {
			t.Fatalf("Failed to exchange token: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("Expected status 200, got %d. Body: %s", resp.StatusCode, string(body))
		}

		var tokenResp map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
			t.Fatalf("Failed to decode token response: %v", err)
		}

		accessToken = tokenResp["access_token"].(string)
		_ = tokenResp["c_nonce"].(string) // cNonce available but not used in this test

		if accessToken == "" {
			t.Fatal("Expected non-empty access token")
		}

		if tokenResp["token_type"] != "Bearer" {
			t.Fatalf("Expected token_type 'Bearer', got %v", tokenResp["token_type"])
		}

		if tokenResp["expires_in"] == nil {
			t.Fatal("Expected expires_in in token response")
		}
	})

	// Test Step 5: Get a fresh nonce
	t.Run("GetNonce", func(t *testing.T) {
		resp, err := http.Post(httpServer.URL+"/oid4vci/api/nonce", "application/json", nil)
		if err != nil {
			t.Fatalf("Failed to get nonce: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("Expected status 200, got %d", resp.StatusCode)
		}

		// Check cache control headers
		cacheControl := resp.Header.Get("Cache-Control")
		if !strings.Contains(cacheControl, "no-store") {
			t.Fatalf("Expected no-store in Cache-Control header, got: %s", cacheControl)
		}

		var nonceResp map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&nonceResp); err != nil {
			t.Fatalf("Failed to decode nonce response: %v", err)
		}

		if nonceResp["nonce"] == nil {
			t.Fatal("Expected nonce in response")
		}

		if nonceResp["c_nonce_expires_in"] == nil {
			t.Fatal("Expected c_nonce_expires_in in response")
		}

		// Fresh nonce available (for future use if needed)
		_ = nonceResp["nonce"].(string)
	})

	// Test Step 6: Request credential without proof (unbound credential)
	t.Run("RequestUnboundCredential", func(t *testing.T) {
		credReq := map[string]interface{}{
			"format": "vc+sd-jwt",
		}

		reqBody, _ := json.Marshal(credReq)
		req, _ := http.NewRequest("POST", httpServer.URL+"/oid4vci/api/credential", bytes.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+accessToken)

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("Failed to request credential: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			t.Fatalf("Expected status 200, got %d. Body: %s", resp.StatusCode, string(body))
		}

		var credResp map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&credResp); err != nil {
			t.Fatalf("Failed to decode credential response: %v", err)
		}

		if credResp["credential"] == nil {
			t.Fatal("Expected credential in response")
		}

		if credResp["format"] != "vc+sd-jwt" {
			t.Fatalf("Expected format 'vc+sd-jwt', got %v", credResp["format"])
		}

		// Verify the credential is a JWT-like structure
		credential := credResp["credential"].(string)
		if !strings.Contains(credential, ".") {
			t.Fatal("Expected credential to be JWT-like structure with dots")
		}

		// Verify it ends with SD-JWT disclosure separator
		if !strings.HasSuffix(credential, "~") {
			t.Fatal("Expected credential to end with SD-JWT disclosure separator '~'")
		}
	})

	// Test Step 7: Test invalid pre-authorized code
	t.Run("InvalidPreAuthorizedCode", func(t *testing.T) {
		formData := url.Values{
			"grant_type":          {"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
			"pre-authorized_code": {"invalid-code"},
		}

		resp, err := http.PostForm(httpServer.URL+"/oid4vci/api/token", formData)
		if err != nil {
			t.Fatalf("Failed to make request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("Expected status 400, got %d", resp.StatusCode)
		}

		var errorResp map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&errorResp); err != nil {
			t.Fatalf("Failed to decode error response: %v", err)
		}

		if errorResp["error"] != "invalid_grant" {
			t.Fatalf("Expected error 'invalid_grant', got %v", errorResp["error"])
		}
	})

	// Test Step 8: Test invalid grant type
	t.Run("InvalidGrantType", func(t *testing.T) {
		formData := url.Values{
			"grant_type":          {"invalid_grant_type"},
			"pre-authorized_code": {preAuthCode},
		}

		resp, err := http.PostForm(httpServer.URL+"/oid4vci/api/token", formData)
		if err != nil {
			t.Fatalf("Failed to make request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("Expected status 400, got %d", resp.StatusCode)
		}

		var errorResp map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&errorResp); err != nil {
			t.Fatalf("Failed to decode error response: %v", err)
		}

		if errorResp["error"] != "invalid_request" {
			t.Fatalf("Expected error 'invalid_request', got %v", errorResp["error"])
		}
	})

	// Test Step 9: Test unsupported credential format
	t.Run("UnsupportedCredentialFormat", func(t *testing.T) {
		// First, create a new offer since the previous one is used
		newOfferRequest := &issuer.CredentialOfferRequest{
			CredentialType: "example_sd_jwt",
			CredentialData: map[string]interface{}{"test": "data"},
		}

		reqBody, _ := json.Marshal(newOfferRequest)
		resp, err := http.Post(
			httpServer.URL+"/management/api/credentials",
			"application/json",
			bytes.NewReader(reqBody),
		)
		if err != nil {
			t.Fatalf("Failed to create new credential offer: %v", err)
		}
		defer resp.Body.Close()

		var newOffer issuer.CredentialOfferResponse
		json.NewDecoder(resp.Body).Decode(&newOffer)

		// Get the new pre-auth code
		resp, _ = http.Get(newOffer.CredentialOfferURI)
		var newOfferDetails map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&newOfferDetails)
		resp.Body.Close()

		newGrants := newOfferDetails["grants"].(map[string]interface{})
		newPreAuthGrant := newGrants["urn:ietf:params:oauth:grant-type:pre-authorized_code"].(map[string]interface{})
		newPreAuthCode := newPreAuthGrant["pre-authorized_code"].(string)

		// Get new access token
		formData := url.Values{
			"grant_type":          {"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
			"pre-authorized_code": {newPreAuthCode},
		}

		resp, _ = http.PostForm(httpServer.URL+"/oid4vci/api/token", formData)
		var newTokenResp map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&newTokenResp)
		resp.Body.Close()

		newAccessToken := newTokenResp["access_token"].(string)

		// Request credential with unsupported format
		credReq := map[string]interface{}{
			"format": "ldp_vc", // Unsupported format
		}

		reqBody, _ = json.Marshal(credReq)
		req, _ := http.NewRequest("POST", httpServer.URL+"/oid4vci/api/credential", bytes.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+newAccessToken)

		client := &http.Client{}
		resp, err = client.Do(req)
		if err != nil {
			t.Fatalf("Failed to make request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("Expected status 400, got %d", resp.StatusCode)
		}

		var errorResp map[string]interface{}
		if err := json.NewDecoder(resp.Body).Decode(&errorResp); err != nil {
			t.Fatalf("Failed to decode error response: %v", err)
		}

		if errorResp["error"] != "credential_creation_error" {
			t.Fatalf("Expected error containing unsupported format, got %v", errorResp["error"])
		}
	})
}

// Helper functions

func createTestIssuerConfig() *issuer.Config {
	return createTestIssuerConfigWithURL("http://localhost:8081")
}

func createTestIssuerConfigWithURL(externalURL string) *issuer.Config {
	return &issuer.Config{
		Server: issuer.ServerConfig{
			Port: "8081",
			Host: "localhost",
		},
		Storage: issuer.StorageConfig{
			Type:            "memory",
			CleanupInterval: 1 * time.Hour,
		},
		Signing: issuer.SigningConfig{
			// No private key for test - will create unsigned credentials
			PrivateKeyPEM:      "",
			VerificationMethod: "did:example:issuer#key-1",
			Algorithm:          "ES256",
		},
		Metadata: issuer.MetadataConfig{
			DisplayInfo: issuer.DisplayInfo{
				Name:   "Test Issuer",
				Locale: "en-US",
				Logo:   "https://example.com/logo.png",
			},
			CredentialsSupported: []issuer.CredentialSupported{
				{
					ID:                                   "example_sd_jwt",
					Format:                               "vc+sd-jwt",
					CryptographicBindingMethodsSupported: []string{"jwk"},
					CredentialSigningAlgValuesSupported:  []string{"ES256"},
					ProofTypesSupported:                  []string{"jwt"},
					CredentialDefinition: issuer.CredentialDefinition{
						Type: []string{"VerifiableCredential", "ExampleCredential"},
						VCT:  "https://example.com/example-credential",
						Claims: map[string]issuer.ClaimInfo{
							"given_name": {
								Mandatory: true,
								Display: []issuer.DisplayInfo{{
									Name:   "Given Name",
									Locale: "en-US",
								}},
							},
							"family_name": {
								Mandatory: true,
								Display: []issuer.DisplayInfo{{
									Name:   "Family Name",
									Locale: "en-US",
								}},
							},
						},
					},
					Display: []issuer.DisplayInfo{{
						Name:   "Example Credential",
						Locale: "en-US",
					}},
				},
			},
		},
		Nonce: issuer.NonceConfig{
			LifetimeSeconds: 300,
		},
		Credential: issuer.CredentialConfig{
			DefaultExpirationHours: 8760,
			DefaultFormat:          "vc+sd-jwt",
		},
		ExternalURL: externalURL,
		IssuerID:    "did:example:test-issuer",
		Profile:     "test",
	}
}

func createIssuerMux(httpServerURL string) http.Handler {
	// Create config with correct external URL
	cfg := createTestIssuerConfigWithURL(httpServerURL)
	storage, _ := issuer.NewStorage(cfg)
	credService := issuer.NewCredentialService(cfg, storage)
	nonceService := issuer.NewNonceService(cfg)
	mgmtService := issuer.NewManagementService(cfg, storage)
	handlers := issuer.NewHandlers(cfg, credService, nonceService, mgmtService)

	mux := http.NewServeMux()
	handlers.RegisterRoutes(mux)
	return mux
}

func intPtr(i int) *int {
	return &i
}
