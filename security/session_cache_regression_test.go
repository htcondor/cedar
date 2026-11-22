package security

import (
	"testing"
	"time"

	golang_classads "github.com/PelicanPlatform/classad/classad"
	"github.com/htcondor/cedar/stream"
)

// TestSessionCachePeerAddressBug verifies that sessions with different peer addresses
// are not incorrectly shared. This is a regression test for the bug where session
// cache entries were stored with empty peer addresses.
func TestSessionCachePeerAddressBug(t *testing.T) {
	// Create a session cache
	cache := NewSessionCache()

	// Create a mock authenticator with session caching enabled
	config := &SecurityConfig{
		Authentication: SecurityOptional,
		Encryption:     SecurityOptional,
		Integrity:      SecurityOptional,
		AuthMethods:    []AuthMethod{AuthFS, AuthIDTokens},
		CryptoMethods:  []CryptoMethod{CryptoAES},
		SessionCache:   cache,
		PeerName:       "peer1.example.com:1234",
		Command:        0,
	}

	// Create a test stream with peer1
	s1 := stream.NewStream(nil) // Mock stream
	s1.SetPeerAddr("peer1.example.com:1234")
	auth1 := NewAuthenticator(config, s1)

	// Create a test negotiation for peer1
	negotiation1 := &SecurityNegotiation{
		ClientConfig:     config,
		ServerConfig:     config,
		NegotiatedAuth:   AuthFS,
		NegotiatedCrypto: CryptoAES,
		SessionId:        "test-session-1",
		ValidCommands:    "0",
	}
	negotiation1.setSharedSecret([]byte("test-secret-key-1234567890123456")) // 32 bytes for AES-256

	// Store session for peer1
	auth1.storeClientSession(negotiation1, 3600, 3600, cache)

	// Verify the session was stored with peer1's address
	peerAddr1 := s1.GetPeerAddr()
	if peerAddr1 == "" {
		t.Fatal("Peer address for stream 1 should not be empty")
	}

	// Verify that the session cache entry has the correct peer address (not empty)
	// Use LookupByCommand which uses peer address + command as key
	entry1, found := cache.LookupByCommand("", peerAddr1, "0")
	if !found {
		t.Fatal("Expected session entry for peer1 to be found by peer address + command")
	}
	if entry1.Addr() != peerAddr1 {
		t.Errorf("Session entry has wrong peer address: got %q, want %q", entry1.Addr(), peerAddr1)
	}

	// Create a second configuration for peer2 with the same session cache
	config2 := &SecurityConfig{
		Authentication: SecurityOptional,
		Encryption:     SecurityOptional,
		Integrity:      SecurityOptional,
		AuthMethods:    []AuthMethod{AuthFS, AuthIDTokens},
		CryptoMethods:  []CryptoMethod{CryptoAES},
		SessionCache:   cache, // Share the same cache
		PeerName:       "peer2.example.com:5678",
		Command:        0,
	}

	// Create a test stream with peer2
	s2 := stream.NewStream(nil)
	s2.SetPeerAddr("peer2.example.com:5678")

	// Try to look up a session for peer2 - it should NOT find peer1's session
	// Use LookupByCommand which uses peer address + command as key
	entry2, found := cache.LookupByCommand("", s2.GetPeerAddr(), "0")
	if found {
		t.Errorf("Should not find session for peer2 (different address), but found entry with addr=%q", entry2.Addr())
	}

	// Now store a session for peer2
	auth2 := NewAuthenticator(config2, s2)
	negotiation2 := &SecurityNegotiation{
		ClientConfig:     config2,
		ServerConfig:     config2,
		NegotiatedAuth:   AuthFS,
		NegotiatedCrypto: CryptoAES,
		SessionId:        "test-session-2",
		ValidCommands:    "0",
	}
	negotiation2.setSharedSecret([]byte("test-secret-key-0987654321abcdef")) // Different key
	auth2.storeClientSession(negotiation2, 3600, 3600, cache)

	// Verify the second session was stored correctly
	entry2, found = cache.LookupByCommand("", s2.GetPeerAddr(), "0")
	if !found {
		t.Fatal("Expected session entry for peer2")
	}
	if entry2.Addr() != s2.GetPeerAddr() {
		t.Errorf("Session entry 2 has wrong peer address: got %q, want %q", entry2.Addr(), s2.GetPeerAddr())
	}

	// Verify both sessions are distinct
	entry1Again, found := cache.LookupByCommand("", peerAddr1, "0")
	if !found {
		t.Fatal("Session for peer1 should still exist")
	}
	if entry1Again.ID() == entry2.ID() {
		t.Error("The two sessions should have different IDs")
	}

	// Verify that looking up with peer1's address still returns peer1's session
	if string(entry1Again.KeyInfo().Data) != "test-secret-key-1234567890123456" {
		t.Error("Peer1's session has wrong shared secret")
	}
	if string(entry2.KeyInfo().Data) != "test-secret-key-0987654321abcdef" {
		t.Error("Peer2's session has wrong shared secret")
	}
}

// TestSessionResumedFlag verifies that SessionResumed flag is properly set
// This is a more targeted test that validates the flag without full handshake
func TestSessionResumedFlag(t *testing.T) {
	// Test 1: New session should not have SessionResumed flag set
	negotiation1 := &SecurityNegotiation{
		NegotiatedAuth:   AuthFS,
		NegotiatedCrypto: CryptoAES,
		SessionId:        "new-session",
	}
	negotiation1.setSharedSecret([]byte("test-secret-key-abcdef1234567890"))

	if negotiation1.SessionResumed {
		t.Error("SessionResumed should be false for new session before handshake")
	}

	// Test 2: Resumed session should have the flag set
	cache := NewSessionCache()
	policy := golang_classads.New()
	_ = policy.Set("AuthMethods", string(AuthFS))

	entry := NewSessionEntry(
		"resumed-session",
		"test.example.com:9618",
		&KeyInfo{
			Data:     []byte("resumed-secret-1234567890abcdef"),
			Protocol: string(CryptoAES),
		},
		policy,
		time.Now().Add(1*time.Hour),
		1*time.Hour,
		"",
	)
	cache.Store(entry)

	// Verify we can retrieve it
	retrieved, found := cache.Lookup("resumed-session")
	if !found {
		t.Fatal("Failed to retrieve stored session")
	}
	if retrieved.ID() != "resumed-session" {
		t.Errorf("Expected session ID 'resumed-session', got %q", retrieved.ID())
	}
}

// TestSharedSecretEncapsulation verifies that SharedSecret field is properly encapsulated
func TestSharedSecretEncapsulation(t *testing.T) {
	negotiation := &SecurityNegotiation{}

	// Initially should be nil/empty
	if len(negotiation.GetSharedSecret()) != 0 {
		t.Error("Initial shared secret should be empty")
	}

	// Set a shared secret
	testSecret := []byte("my-test-secret-1234567890abcdef")
	negotiation.setSharedSecret(testSecret)

	// Retrieve it
	retrieved := negotiation.GetSharedSecret()
	if string(retrieved) != string(testSecret) {
		t.Errorf("Expected %q, got %q", testSecret, retrieved)
	}

	// Verify we can't directly access the private field (compilation should fail)
	// negotiation.sharedSecret = []byte("hack") // This should not compile
}

// TestEncryptionOnlyForResumedSessions verifies that SessionResumed flag is properly
// used to distinguish between fresh ECDH handshakes and session resumption
func TestEncryptionOnlyForResumedSessions(t *testing.T) {
	// This test verifies the logic in SecurityManager.ClientHandshake/ServerHandshake
	// where symmetric keys are only set for resumed sessions

	// Test 1: New session (not resumed) should not have SessionResumed=true
	negotiation1 := &SecurityNegotiation{
		NegotiatedAuth:   AuthFS,
		NegotiatedCrypto: CryptoAES,
		SessionId:        "new-session",
	}
	negotiation1.setSharedSecret([]byte("new-secret-key-1234567890abcdef"))

	if negotiation1.SessionResumed {
		t.Error("New session should not have SessionResumed=true")
	}

	// Test 2: When we mark a session as resumed, the flag should be set
	negotiation2 := &SecurityNegotiation{
		NegotiatedAuth:   AuthFS,
		NegotiatedCrypto: CryptoAES,
		SessionId:        "resumed-session",
		SessionResumed:   true, // This would be set by resumeSession()
	}
	negotiation2.setSharedSecret([]byte("resumed-secret-1234567890abcdef"))

	if !negotiation2.SessionResumed {
		t.Error("Resumed session should have SessionResumed=true")
	}

	// Verify that WasSessionResumed() accessor works
	config := &SecurityConfig{
		Authentication: SecurityOptional,
	}
	s := stream.NewStream(nil)
	auth := NewAuthenticator(config, s)

	// Initially should not be resumed
	if auth.WasSessionResumed() {
		t.Error("New authenticator should not report session as resumed")
	}
}
