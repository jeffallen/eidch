# EID-CH Issuer Service - Go Port

A Go port of the [Swiss EID-CH Issuer Service](https://github.com/swiyu-admin-ch/swiyu-issuer), implementing OpenID4VCI (OpenID for Verifiable Credential Issuance) specification using only Go standard library dependencies.

## Overview

This service is a credential issuer that handles the issuance of verifiable credentials according to the OpenID4VCI specification. It provides REST endpoints for:

- Serving issuer metadata and well-known configurations
- Creating and managing credential offers
- Issuing OAuth access tokens for pre-authorized flows
- Issuing verifiable credentials in SD-JWT format
- Managing credential lifecycle and status

## Architecture

The issuer service follows clean architecture principles:

```
cmd/issuer-server/           # Main application entry point
issuer/
├── config.go               # Configuration management
├── server.go               # Server setup and lifecycle
├── models.go               # Domain models and data structures
├── storage.go              # Storage interfaces and implementations
├── services.go             # Business logic services
└── handlers.go             # HTTP request handlers
```

### Key Components

- **CredentialService**: Core business logic for credential issuance
- **ManagementService**: Credential offer lifecycle management
- **NonceService**: Secure nonce generation and validation
- **Storage Layer**: Pluggable storage with memory and JSON file implementations
- **Handlers**: HTTP request processing and OpenID4VCI endpoints

## Features

- ✅ OpenID4VCI compliant endpoints
- ✅ SD-JWT (Selective Disclosure JWT) credential format
- ✅ Pre-authorized code flow
- ✅ Credential offer management
- ✅ Nonce-based proof validation
- ✅ Configurable storage backends
- ✅ Well-known metadata endpoints
- ✅ Comprehensive error handling
- ✅ End-to-end test coverage

## API Endpoints

### Well-Known Endpoints

- `GET /.well-known/openid-configuration` - OpenID Connect configuration
- `GET /.well-known/oauth-authorization-server` - OAuth authorization server metadata
- `GET /.well-known/openid-credential-issuer` - Issuer metadata

### OID4VCI API Endpoints

- `POST /oid4vci/api/token` - Exchange pre-authorized code for access token
- `POST /oid4vci/api/nonce` - Generate fresh nonce for proof-of-possession
- `POST /oid4vci/api/credential` - Issue credential with access token
- `POST /oid4vci/api/deferred_credential` - Handle deferred credential issuance

### Management API Endpoints

- `POST /management/api/credentials` - Create new credential offer
- `GET /management/api/credentials/{id}` - Get credential offer details
- `PUT /management/api/credentials/{id}/status` - Update credential offer status

### Other Endpoints

- `GET /credential-offer?offer_id={id}` - Get credential offer for wallets
- `GET /health` - Health check endpoint

## Configuration

The service is configured via environment variables:

### Required Variables

- `EXTERNAL_URL`: Public URL of this issuer instance
- `ISSUER_ID`: DID identifier of this issuer
- `VERIFICATION_METHOD`: Full DID with fragment for credential signing

### Optional Variables

- `SERVER_PORT`: Port to listen on (default: 8080)
- `SERVER_HOST`: Host to bind to (default: localhost)
- `STORAGE_TYPE`: Storage backend - "memory" or "jsonfile" (default: memory)
- `STORAGE_DATA_DIR`: Directory for JSON file storage (default: ./issuer-data)
- `SIGNING_KEY`: PEM-encoded EC private key for credential signing
- `SIGNING_ALGORITHM`: Signing algorithm (default: ES256)
- `NONCE_LIFETIME_SECONDS`: Nonce validity period (default: 300)
- `CREDENTIAL_EXPIRATION_HOURS`: Default credential validity (default: 8760)
- `CREDENTIALS_SUPPORTED_FILE`: Path to credentials supported JSON file
- `ISSUER_DISPLAY_NAME`: Display name for the issuer
- `ISSUER_LOGO_URI`: Logo URI for the issuer

### Example Configuration

```bash
export EXTERNAL_URL="https://issuer.example.com"
export ISSUER_ID="did:example:issuer123"
export VERIFICATION_METHOD="did:example:issuer123#key-1"
export STORAGE_TYPE="jsonfile"
export STORAGE_DATA_DIR="./issuer-data"
export SIGNING_KEY="-----BEGIN EC PRIVATE KEY-----\n..."
export ISSUER_DISPLAY_NAME="Example University"
```

## Running the Service

### Build and Run

```bash
# Build the service
go build -o issuer-server ./cmd/issuer-server

# Set required environment variables
export EXTERNAL_URL="http://localhost:8080"
export ISSUER_ID="did:example:test-issuer"
export VERIFICATION_METHOD="did:example:test-issuer#key-1"

# Run the service
./issuer-server
```

### Using Go Run

```bash
EXTERNAL_URL="http://localhost:8080" \
ISSUER_ID="did:example:test-issuer" \
VERIFICATION_METHOD="did:example:test-issuer#key-1" \
go run ./cmd/issuer-server
```

## Testing

### Run End-to-End Tests

```bash
go test -v -run TestIssuerEndToEndFlow .
```

The end-to-end test reproduces the complete credential issuance flow from the original Java implementation:

1. **Well-Known Configuration**: Tests all metadata endpoints
2. **Credential Offer Creation**: Creates offers via management API
3. **Credential Offer Retrieval**: Tests wallet-facing offer endpoint
4. **Token Exchange**: Tests pre-authorized code to access token exchange
5. **Nonce Generation**: Tests secure nonce creation
6. **Credential Issuance**: Tests unbound credential issuance
7. **Error Handling**: Tests various error scenarios

## Credential Issuance Flow

```mermaid
sequenceDiagram
    participant Issuer as Issuer System
    participant Service as Issuer Service
    participant Wallet as Wallet

    Note over Issuer,Wallet: 1. Credential Offer Creation
    Issuer->>Service: POST /management/api/credentials
    Service->>Issuer: {offer_id, deep_link}
    Issuer->>Wallet: Share deep_link (QR code, etc.)

    Note over Issuer,Wallet: 2. Credential Offer Processing
    Wallet->>Service: GET /credential-offer?offer_id=...
    Service->>Wallet: {credential_issuer, grants}

    Note over Issuer,Wallet: 3. Token Exchange
    Wallet->>Service: POST /oid4vci/api/token {pre-authorized_code}
    Service->>Wallet: {access_token, c_nonce}

    Note over Issuer,Wallet: 4. Credential Issuance
    Wallet->>Service: POST /oid4vci/api/credential {access_token, proof?}
    Service->>Wallet: {credential (SD-JWT)}
```

## Storage Backends

### Memory Storage

Default storage for development and testing. All data is lost when the service stops.

```bash
export STORAGE_TYPE="memory"
```

### JSON File Storage

Persistent storage using JSON files. Each credential offer is stored as a separate file.

```bash
export STORAGE_TYPE="jsonfile"
export STORAGE_DATA_DIR="./issuer-data"
```

### Custom Storage

Implement the `Storage` interface for custom backends (e.g., PostgreSQL, MySQL):

```go
type Storage interface {
    SaveCredentialOffer(offer *CredentialOffer) error
    GetCredentialOffer(id string) (*CredentialOffer, error)
    GetCredentialOfferByPreAuthCode(code string) (*CredentialOffer, error)
    // ... other methods
}
```

## Credential Types

The service supports configurable credential types via the `CREDENTIALS_SUPPORTED_FILE`:

```json
[
  {
    "id": "university_degree",
    "format": "vc+sd-jwt",
    "cryptographic_binding_methods_supported": ["jwk"],
    "credential_signing_alg_values_supported": ["ES256"],
    "proof_types_supported": ["jwt"],
    "credential_definition": {
      "type": ["VerifiableCredential", "UniversityDegreeCredential"],
      "vct": "https://university.example.com/degree-credential",
      "claims": {
        "degree_type": {"mandatory": true},
        "graduation_date": {"mandatory": true},
        "gpa": {"mandatory": false}
      }
    },
    "display": [
      {
        "name": "University Degree",
        "locale": "en-US"
      }
    ]
  }
]
```

## Differences from Original Java Implementation

### Simplified Features

- **Credential Signing**: Uses basic JWT signing (no advanced cryptographic features)
- **Deferred Issuance**: Placeholder implementation
- **Status Lists**: Simplified status management
- **Database Integration**: File-based and in-memory storage instead of PostgreSQL
- **Advanced Security**: Basic validation (no full cryptographic verification)

### Go-Specific Improvements

- **No External Dependencies**: Uses only Go standard library
- **Clean Architecture**: Clear separation of concerns
- **Comprehensive Testing**: Full end-to-end test coverage
- **Pluggable Components**: Easy to extend and customize
- **Minimal Resource Usage**: Lightweight and efficient

## Security Considerations

⚠️ **Important**: This is a simplified implementation for development and testing. For production:

- Implement proper credential signing with secure key management
- Add comprehensive input validation and sanitization
- Use secure storage backends with encryption
- Implement proper authentication and authorization
- Add rate limiting and DDoS protection
- Use HTTPS and secure communication channels
- Implement proper logging and monitoring
- Add credential status list management
- Validate holder proofs cryptographically

## Development

### Project Structure

- **Minimal main.go**: Configuration loading and server instantiation only
- **Library approach**: All functionality in the `issuer` package
- **Standard Go layout**: Following Go project conventions
- **Test coverage**: Comprehensive end-to-end testing

### Adding New Features

1. **New credential formats**: Extend `createCredential` method
2. **Storage backends**: Implement the `Storage` interface
3. **Authentication**: Add middleware to handlers
4. **Advanced validation**: Extend the `validateProof` method

## Interoperability

This Go implementation follows the same OpenID4VCI specification as the original Java version:

- Compatible API endpoints and response formats
- Same error codes and messages
- Standard-compliant credential formats
- Interoperable with compliant wallets and systems

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Contributing

Contributions welcome! Please:

1. Follow Go best practices and conventions
2. Add tests for new functionality  
3. Update documentation as needed
4. Ensure backward compatibility with OpenID4VCI spec
