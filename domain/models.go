package domain

import (
	"time"
)

// VerificationStatus represents the status of a verification process
type VerificationStatus string

const (
	VerificationStatusPending   VerificationStatus = "PENDING"
	VerificationStatusSucceeded VerificationStatus = "SUCCEEDED"
	VerificationStatusFailed    VerificationStatus = "FAILED"
	VerificationStatusExpired   VerificationStatus = "EXPIRED"
)

// VerificationError represents different types of verification errors
type VerificationError string

const (
	VerificationErrorInvalidRequest                     VerificationError = "invalid_request"
	VerificationErrorAuthorizationRequestMissingParam   VerificationError = "authorization_request_missing_error_param"
	VerificationErrorAuthorizationRequestObjectNotFound VerificationError = "authorization_request_object_not_found"
	VerificationErrorVerificationProcessClosed          VerificationError = "verification_process_closed"
	VerificationErrorInvalidPresentationDefinition      VerificationError = "invalid_presentation_definition"
)

// VerificationErrorResponseCode represents specific error response codes
type VerificationErrorResponseCode string

const (
	CredentialInvalid             VerificationErrorResponseCode = "credential_invalid"
	JWTExpired                    VerificationErrorResponseCode = "jwt_expired"
	MissingNonce                  VerificationErrorResponseCode = "missing_nonce"
	InvalidFormat                 VerificationErrorResponseCode = "invalid_format"
	CredentialExpired             VerificationErrorResponseCode = "credential_expired"
	UnsupportedFormat             VerificationErrorResponseCode = "unsupported_format"
	CredentialRevoked             VerificationErrorResponseCode = "credential_revoked"
	CredentialSuspended           VerificationErrorResponseCode = "credential_suspended"
	CredentialMissingData         VerificationErrorResponseCode = "credential_missing_data"
	UnresolvableStatusList        VerificationErrorResponseCode = "unresolvable_status_list"
	PublicKeyOfIssuerUnresolvable VerificationErrorResponseCode = "public_key_of_issuer_unresolvable"
	IssuerNotAccepted             VerificationErrorResponseCode = "issuer_not_accepted"
	HolderBindingMismatch         VerificationErrorResponseCode = "holder_binding_mismatch"
	ClientRejected                VerificationErrorResponseCode = "client_rejected"
	InvalidPresentationSubmission VerificationErrorResponseCode = "invalid_presentation_submission"
)

// ManagementEntity represents a verification process
type ManagementEntity struct {
	ID                             string                  `json:"id"`
	RequestNonce                   string                  `json:"request_nonce"`
	State                          VerificationStatus      `json:"state"`
	JWTSecuredAuthorizationRequest bool                    `json:"jwt_secured_authorization_request"`
	RequestedPresentation          *PresentationDefinition `json:"requested_presentation"`
	WalletResponse                 *ResponseData           `json:"wallet_response"`
	ExpirationInSeconds            int                     `json:"expiration_in_seconds"`
	CreatedAt                      time.Time               `json:"created_at"`
	UpdatedAt                      time.Time               `json:"updated_at"`
}

// IsExpired checks if the verification process has expired
func (m *ManagementEntity) IsExpired() bool {
	return time.Since(m.CreatedAt) > time.Duration(m.ExpirationInSeconds)*time.Second
}

// IsVerificationPending checks if verification is still pending
func (m *ManagementEntity) IsVerificationPending() bool {
	return m.State == VerificationStatusPending && !m.IsExpired()
}

// VerificationSucceeded marks the verification as succeeded
func (m *ManagementEntity) VerificationSucceeded(credentialSubjectData string) {
	m.State = VerificationStatusSucceeded
	m.UpdatedAt = time.Now()
	if m.WalletResponse == nil {
		m.WalletResponse = &ResponseData{}
	}
	m.WalletResponse.CredentialSubjectData = credentialSubjectData
}

// VerificationFailed marks the verification as failed
func (m *ManagementEntity) VerificationFailed(errorType VerificationError, errorCode VerificationErrorResponseCode) {
	m.State = VerificationStatusFailed
	m.UpdatedAt = time.Now()
	if m.WalletResponse == nil {
		m.WalletResponse = &ResponseData{}
	}
	m.WalletResponse.ErrorType = string(errorType)
	m.WalletResponse.ErrorCode = string(errorCode)
}

// VerificationFailedDueToClientRejection marks the verification as failed due to client rejection
func (m *ManagementEntity) VerificationFailedDueToClientRejection(errorDescription string) {
	m.State = VerificationStatusFailed
	m.UpdatedAt = time.Now()
	if m.WalletResponse == nil {
		m.WalletResponse = &ResponseData{}
	}
	m.WalletResponse.ErrorType = string(VerificationErrorInvalidRequest)
	m.WalletResponse.ErrorCode = string(ClientRejected)
	m.WalletResponse.ErrorDescription = errorDescription
}

// PresentationDefinition represents the definition of what needs to be presented
type PresentationDefinition struct {
	ID               string            `json:"id"`
	Name             string            `json:"name,omitempty"`
	Purpose          string            `json:"purpose,omitempty"`
	InputDescriptors []InputDescriptor `json:"input_descriptors"`
}

// InputDescriptor describes the required input for verification
type InputDescriptor struct {
	ID          string                 `json:"id"`
	Name        string                 `json:"name,omitempty"`
	Purpose     string                 `json:"purpose,omitempty"`
	Format      map[string]interface{} `json:"format,omitempty"`
	Constraints *Constraints           `json:"constraints,omitempty"`
}

// Constraints defines constraints for the input descriptor
type Constraints struct {
	Fields          []Field `json:"fields,omitempty"`
	LimitDisclosure string  `json:"limit_disclosure,omitempty"`
}

// Field defines a field constraint
type Field struct {
	Path   []string               `json:"path"`
	Filter map[string]interface{} `json:"filter,omitempty"`
}

// ResponseData represents the response from wallet
type ResponseData struct {
	CredentialSubjectData string `json:"credential_subject_data,omitempty"`
	ErrorType             string `json:"error_type,omitempty"`
	ErrorCode             string `json:"error_code,omitempty"`
	ErrorDescription      string `json:"error_description,omitempty"`
}

// RequestObject represents the OpenID4VP request object
type RequestObject struct {
	Nonce                  string                  `json:"nonce"`
	Version                string                  `json:"version"`
	PresentationDefinition *PresentationDefinition `json:"presentation_definition"`
	ClientID               string                  `json:"client_id"`
	ClientMetadata         map[string]interface{}  `json:"client_metadata"`
	ClientIDScheme         string                  `json:"client_id_scheme"`
	ResponseType           string                  `json:"response_type"`
	ResponseMode           string                  `json:"response_mode"`
	ResponseURI            string                  `json:"response_uri"`
}

// PresentationSubmission represents the submission from wallet
type PresentationSubmission struct {
	ID            string          `json:"id"`
	DefinitionID  string          `json:"definition_id"`
	DescriptorMap []DescriptorMap `json:"descriptor_map"`
}

// DescriptorMap maps input descriptors to the presentation format
type DescriptorMap struct {
	ID     string `json:"id"`
	Format string `json:"format"`
	Path   string `json:"path"`
}

// VerificationPresentationRequest represents the request from wallet
type VerificationPresentationRequest struct {
	VPToken                string `json:"vp_token"`
	PresentationSubmission string `json:"presentation_submission"`
	Error                  string `json:"error"`
	ErrorDescription       string `json:"error_description"`
}

// IsClientRejection checks if the request represents a client rejection
func (r *VerificationPresentationRequest) IsClientRejection() bool {
	return r.Error != "" && r.Error == "access_denied"
}
