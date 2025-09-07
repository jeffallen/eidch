# EID-CH Verifier Agent OID4VP - Go Port

A simple Go port of the [Swiss EID-CH Verifier Agent OID4VP](https://github.com/swiyu-admin-ch/eidch-verifier-agent-oid4vp) service, implementing OpenID4VP (OpenID for Verifiable Presentations) specification using only Go standard library dependencies.

## Overview

This service is a verifier agent that handles verification of verifiable credentials according to the OpenID4VP specification. It provides REST endpoints for:

- Serving client metadata
- Creating and serving request objects
- Receiving and verifying presentations from wallets

## Architecture

The application follows clean architecture principles with clear separation of concerns:

```
├── cmd/verification-server/    # Application entry point
├── config/                     # Configuration management
├── domain/                     # Domain models and business logic
├── service/                    # Business services
├── storage/                    # Data persistence layer
├── handlers/                   # HTTP request handlers
├── jwt/                        # JWT utilities (stdlib only)
└── e2e_test.go                 # End-to-end integration tests
```

### Key Components

- **VerificationService**: Core business logic for processing verification presentations
- **RequestObjectService**: Handles creation and signing of request objects
- **Storage Layer**: Pluggable storage with in-memory and JSON file implementations
- **JWT Support**: Basic JWT creation and parsing using only Go standard library

## Features

- ✅ OpenID4VP compliant endpoints
- ✅ SD-JWT (Selective Disclosure JWT) credential verification (simplified)
- ✅ Client metadata serving
- ✅ Request object creation (both JSON and signed JWT)
- ✅ Verification presentation processing
- ✅ Client rejection handling
- ✅ Configurable storage backends (memory, JSON files)
- ✅ Comprehensive error handling
- ✅ Full test coverage including E2E tests

## API Endpoints

### GET /api/v1/openid-client-metadata.json
Returns verifier metadata including client name, logo, and supported features.

### GET /api/v1/request-object/{request_id}
Returns a request object for the specified verification process. Can return either:
- JSON format (if JWT signing is disabled)
- Signed JWT format (if JWT signing is enabled)

### POST /api/v1/request-object/{request_id}/response-data
Receives verification presentation from a wallet. Accepts form-encoded data:
- `vp_token`: The verifiable presentation token
- `presentation_submission`: JSON describing how the presentation fulfills requirements
- `error`: Error code if wallet rejected the request
- `error_description`: Human-readable error description

### GET /health
Health check endpoint.

## Configuration

The service is configured via environment variables:

### Required Variables

- `EXTERNAL_URL`: Public URL of this service instance
- `VERIFIER_DID`: DID identifier of this verifier
- `DID_VERIFICATION_METHOD`: Full DID with fragment for public key verification

### Optional Variables

- `SERVER_PORT`: Port to listen on (default: 8080)
- `SERVER_HOST`: Host to bind to (default: localhost)
- `PROFILE`: Application profile (default: local)
- `STORAGE_TYPE`: Storage backend type - "memory" or "jsonfile" (default: memory)
- `STORAGE_DATA_DIR`: Directory for JSON file storage (default: ./data)
- `SIGNING_KEY`: PEM-encoded EC private key for JWT signing
- `OPENID_CLIENT_METADATA_FILE`: Path to client metadata JSON file
- `EXPIRATION_DURATION`: How long verification processes remain valid (default: 5m)

### Example Configuration

```bash
export EXTERNAL_URL="https://verifier.example.com"
export VERIFIER_DID="did:example:verifier123"
export DID_VERIFICATION_METHOD="did:example:verifier123#key-1"
export STORAGE_TYPE="jsonfile"
export STORAGE_DATA_DIR="./verification-data"
```

## Running the Service

### Build and Run

```bash
# Build the service
go build -o verification-server ./cmd/verification-server

# Set required environment variables
export EXTERNAL_URL="http://localhost:8080"
export VERIFIER_DID="did:example:test-verifier"
export DID_VERIFICATION_METHOD="did:example:test-verifier#key-1"

# Run the service
./verification-server
```

### Using Go Run

```bash
# Set environment variables and run
EXTERNAL_URL="http://localhost:8080" \
VERIFIER_DID="did:example:test-verifier" \
DID_VERIFICATION_METHOD="did:example:test-verifier#key-1" \
go run ./cmd/verification-server
```

## Testing

### Run All Tests

```bash
go test ./...
```

### Run End-to-End Tests

```bash
go test -v -run TestEndToEndVerificationFlow .
```

### Run Specific Package Tests

```bash
# Test storage layer
go test ./storage/...

# Test services
go test ./service/...
```

## Storage Backends

### Memory Storage

Default storage backend that keeps all data in memory. Suitable for development and testing.

```bash
export STORAGE_TYPE="memory"
```

### JSON File Storage

Stores each verification process as a separate JSON file in a directory. Suitable for simple deployments.

```bash
export STORAGE_TYPE="jsonfile"
export STORAGE_DATA_DIR="./data"
```

### Custom SQL Storage

Users can implement the `storage.Repository` interface to add SQL database support:

```go
type Repository interface {
    Save(entity *domain.ManagementEntity) error
    FindByID(id string) (*domain.ManagementEntity, error)
    Delete(id string) error
    CleanupExpired() error
    Close() error
}
```

## Verification Flow

1. **Management Service** creates a verification process and stores it in the database
2. **Wallet** requests the verification object via `GET /api/v1/request-object/{id}`
3. **Service** returns request object (JSON or signed JWT) with presentation requirements
4. **Wallet** presents credentials via `POST /api/v1/request-object/{id}/response-data`
5. **Service** validates the presentation and updates the verification status
6. **Management Service** can query the verification result

## Differences from Original Java Implementation

### Simplified Features

- **SD-JWT Verification**: Simplified implementation without full cryptographic verification
- **DID Resolution**: Mock implementation (not actual DID document resolution)
- **Status List Checking**: Simplified status validation
- **HSM Support**: Not implemented (only PEM key support)
- **Database Integration**: File-based and in-memory storage instead of PostgreSQL

### Go-Specific Improvements

- **No External Dependencies**: Uses only Go standard library
- **Clean Architecture**: Clear separation between domain, service, and infrastructure layers
- **Comprehensive Testing**: Full test coverage including integration tests
- **Pluggable Storage**: Easy to extend with custom storage implementations

## Development

### Project Structure

```
├── cmd/verification-server/main.go    # Application entry point
├── config/config.go                   # Configuration management
├── domain/models.go                   # Domain models and business rules
├── service/                           # Business logic layer
│   ├── request_object.go              # Request object creation
│   ├── verification.go                # Verification processing
│   └── verification_test.go           # Service tests
├── storage/                           # Data persistence layer
│   ├── interface.go                   # Storage interfaces
│   ├── memory.go                      # In-memory implementation
│   ├── jsonfile.go                    # JSON file implementation
│   ├── factory.go                     # Storage factory
│   └── jsonfile_test.go               # Storage tests
├── handlers/handler.go                # HTTP request handlers
├── jwt/jwt.go                         # JWT utilities
├── e2e_test.go                        # End-to-end tests
├── go.mod                             # Go module definition
└── README.md                          # This file
```

### Adding New Storage Backends

1. Implement the `storage.Repository` interface
2. Add factory support in `storage/factory.go`
3. Add configuration options in `config/config.go`
4. Add tests for the new implementation

### Adding New Credential Formats

1. Extend the `verifyCredential` method in `service/verification.go`
2. Add format-specific verification logic
3. Update the `domain.InputDescriptor` format specifications
4. Add tests for the new format

## Interoperability

This Go port is designed to be interoperable with the original Java implementation and other OpenID4VP implementations. It follows the same:

- REST API endpoints and response formats
- Error codes and messages
- Request object structure
- Presentation submission format

For full interoperability testing, you can:

1. Run this service alongside the original Java implementation
2. Use the same client metadata and presentation definitions
3. Test with real wallet implementations
4. Verify error handling and edge cases

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please:

1. Follow Go conventions and best practices
2. Add tests for new functionality
3. Update documentation as needed
4. Ensure all tests pass before submitting

## Security Considerations

⚠️ **Important**: This is a simplified implementation intended for development and testing purposes. For production use:

- Implement proper JWT signature verification
- Add real DID document resolution
- Implement comprehensive status list checking
- Add proper cryptographic validation
- Use secure storage backends
- Implement proper logging and monitoring
- Add rate limiting and other security measures
