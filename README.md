# cedar

A Go implementation of HTCondor's CEDAR binary protocol.

## Overview

This library provides a low-level interface for creating and receiving messages using HTCondor's CEDAR protocol over TCP sockets. CEDAR (ClassAd Evaluation Daemon And Repository) is the binary protocol used for communication between HTCondor daemons and clients.

## Features

- **Stream Management**: Low-level TCP socket handling with message framing
- **Message Serialization**: Binary serialization of C++ types compatible with HTCondor
- **ClassAd Support**: Serialization/deserialization of HTCondor ClassAd structures
- **Security**: Authentication and encryption (SSL, SCITOKENS, IDTOKENS)
- **HTCondor Clients**: High-level clients for HTCondor API operations

## Project Structure

```
├── commands/        # HTCondor command constants and utilities
├── stream/          # TCP socket stream management and message framing
├── message/         # Message serialization and deserialization
├── security/        # Authentication and encryption protocols
├── client/          # HTCondor API client implementations
├── protocol/        # Binary protocol documentation
└── main.go          # Example usage
```

## Key Components
- `commands/`: HTCondor command constants and utilities
- `stream/`: TCP socket stream management and message framing
- `message/`: Message serialization and deserialization
- `security/`: Authentication and encryption protocols
- `client/`: HTCondor API client implementations
- `protocol/`: Binary protocol documentation and specifications

**External Dependencies:**
- [PelicanPlatform/classad](https://github.com/PelicanPlatform/classad): ClassAd parsing and evaluation

## Development Roadmap

### Phase 1: Core Protocol ✅ COMPLETED
- [x] HTCondor-compatible CEDAR packet framing
- [x] Message encoding/decoding with proper header format
- [x] Support for complete and partial messages
- [x] Validation and size limits matching HTCondor
- [x] End-of-Message (EOM) handling with multi-frame support
- [x] Complete type serialization/deserialization system
- [x] HTCondor's frexp/ldexp double encoding
- [x] ClassAd binary serialization (HTCondor wire format)
- [x] Advanced ClassAd serialization options (private attribute filtering, whitelists, etc.)

### Phase 2: Security ✅ COMPLETED
- [x] Security handshake protocol (DC_AUTHENTICATE)
- [x] Authentication method negotiation (SSL, TOKEN, FS, etc.)
- [x] Encryption method negotiation (AES, BLOWFISH, 3DES)
- [x] Security policy negotiation (REQUIRED/OPTIONAL/NEVER)
- [x] ECDH key exchange support
- [x] HTCondor-compatible ClassAd security exchange
- [x] AES-256-GCM encryption with HTCondor-compatible AAD mechanism
- [x] HKDF key derivation from ECDH shared secrets
- [x] Complete authenticated encryption implementation
- [ ] SSL certificate validation
- [ ] Token validation and generation

### Phase 2.5: Command System ✅ COMPLETED
- [x] HTCondor command constant enumeration (condor_commands.h)
- [x] Command metadata and categorization system
- [x] Session command specification in security handshake
- [x] Type-safe command handling utilities
- [x] Integration with authentication protocol

### Phase 3: Clients
- [ ] Collector query client (condor_status equivalent)
- [ ] Additional HTCondor API clients

## Usage

### ClassAd Serialization

```go
package main

import (
    "fmt"
    "github.com/PelicanPlatform/classad/classad"
    "github.com/htcondor/cedar/message"
)

func main() {
    // Create a ClassAd
    ad := classad.New()
    ad.Set("Arch", "x86_64")
    ad.Set("Memory", 8192)
    ad.Set("MyType", "Machine")
    ad.Set("Capability", "0xdeadbeef")  // Private attribute

    // Basic serialization using Message API with a Stream
    msg := message.NewMessageForStream(cedarStream)
    if err := msg.PutClassAd(ad); err != nil {
        panic(err)
    }
    if err := msg.FinishMessage(); err != nil {
        panic(err)
    }

    // Advanced serialization with options
    config := &message.PutClassAdConfig{
        Options:     message.NoPrivate | message.ServerTime,
        PeerVersion: "8.9.6",  // HTCondor version compatibility
    }
    msg2 := message.NewMessageForStream(cedarStream)
    if err := msg2.PutClassAdWithOptions(ad, config); err != nil {
        panic(err)
    }

    // Private attributes are excluded from msg2
    fmt.Printf("Basic: %d bytes, NoPrivate: %d bytes\n", len(msg.Bytes()), len(msg2.Bytes()))
}
```

### Private Attribute Handling

```go
// Check if an attribute is considered private
isPrivate := message.ClassAdAttributeIsPrivateAny("Capability", "8.9.6")
fmt.Printf("'Capability' is private: %v\n", isPrivate)  // true

// Whitelist filtering
config := &message.PutClassAdConfig{
    Options:      message.NoExpandWhitelist,
    AttributeWhiteList: []string{"Arch", "Memory"},  // Only these attributes
}
```

### Security Handshake

```go
package main

import (
    "context"
    "log"
    "github.com/htcondor/cedar/client"
    "github.com/htcondor/cedar/security"
)

func main() {
    // Connect to HTCondor daemon using client package
    htcondorClient, err := client.ConnectToAddress(
        context.Background(),
        "condor.example.com:9618",
        0, // default timeout
    )
    if err != nil {
        log.Fatal(err)
    }
    defer htcondorClient.Close()

    // Get the stream and configure security
    s := htcondorClient.GetStream()
    config := &security.SecurityConfig{
        AuthMethods:   []security.AuthMethod{security.AuthToken, security.AuthSSL},
        CryptoMethods: []security.CryptoMethod{security.CryptoAES},
        Authentication: security.SecurityRequired,
        Encryption:    security.SecurityRequired,
        TrustDomain:   "htcondor.example.com",
        ECDHPublicKey: "base64-encoded-public-key",
    }

    // Perform security handshake
    auth := security.NewAuthenticator(config, s)
    negotiation, err := auth.ClientHandshake(context.Background())
    if err != nil {
        log.Fatal(err)
    }

    if negotiation.Enact {
        log.Printf("Secure session established using %s auth and %s encryption",
            negotiation.NegotiatedAuth, negotiation.NegotiatedCrypto)
    }
}
```

### Stream Operations with EOM

```go
// Create a stream from TCP connection
stream := stream.NewStream(conn)

// Send multi-part message with EOM
stream.StartMessage()
stream.WriteMessage([]byte("Part 1: "))
stream.WriteMessage([]byte("Part 2"))
stream.EndMessage() // Automatically sends with complete flag

// Receive complete message
received, err := stream.ReceiveCompleteMessage()
if err != nil {
    log.Fatal(err)
}
```

## Reference Implementation

This implementation is based on HTCondor's C++ codebase:
- Stream serialization: `~/projects/htcondor/src/condor_io/stream.cpp`
- Socket framing: `~/projects/htcondor/src/condor_io/reli_sock.cpp`
- ClassAd handling: `~/projects/htcondor/src/condor_utils/classad_oldnew.cpp`

## Getting Started

### Local Development

```bash
# Clone the repository
git clone https://github.com/htcondor/cedar
cd cedar

# Install dependencies
go mod tidy

# Run tests
go test ./...

# Run integration tests (requires HTCondor)
go test ./security -run Integration -v

# Build examples
go build ./examples/simple_startd_query.go
```

### Using Docker

All Docker-based tests run as the non-root `runner` user for security.

#### Run tests in Docker

```bash
# Run all tests
docker-compose up test

# Run unit tests only (skip integration tests)
docker-compose up test-unit

# Run integration tests
docker-compose up test-integration

# Run with coverage
docker-compose up test-coverage

# Build the package
docker-compose up build
```

#### Build and run manually

```bash
# Build the test container
docker build -t golang-cedar-test .

# Run tests
docker run --rm golang-cedar-test

# Run specific tests
docker run --rm golang-cedar-test go test -v ./security

# Interactive shell
docker run -it --rm golang-cedar-test /bin/bash
```

### GitHub Codespaces / VS Code Dev Containers

This project includes a complete development container configuration:

1. **GitHub Codespaces**: Click "Code" → "Codespaces" → "Create codespace"
2. **VS Code Dev Containers**:
   - Install [Dev Containers extension](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers)
   - Open project and click "Reopen in Container"

The dev container includes:
- Go 1.23.4
- HTCondor 23.x (full installation)
- All Go development tools (gopls, delve, staticcheck)
- Pre-commit hooks

See [.devcontainer/README.md](.devcontainer/README.md) for details.

## Documentation

See [protocol/CEDAR_PROTOCOL.md](protocol/CEDAR_PROTOCOL.md) for detailed protocol specification.

## License

This project is licensed under the Apache License 2.0.
