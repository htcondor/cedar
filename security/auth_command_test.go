package security

import (
	"testing"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/htcondor/cedar/commands"
)

// TestAuthCommandInClientAd tests that AuthCommand is included in client security ClassAd when set
func TestAuthCommandInClientAd(t *testing.T) {
	t.Run("with_auth_command", func(t *testing.T) {
		config := &SecurityConfig{
			AuthMethods:    []AuthMethod{AuthFS, AuthToken},
			CryptoMethods:  []CryptoMethod{CryptoAES},
			Authentication: SecurityOptional,
			Encryption:     SecurityOptional,
			Integrity:      SecurityOptional,
			Command:        commands.DC_SEC_QUERY,
			AuthCommand:    commands.DC_NOP_WRITE,
		}

		auth := &Authenticator{
			config: config,
		}

		ad := auth.createClientSecurityAd()

		// Verify Command is set
		if cmd, ok := ad.EvaluateAttrInt("Command"); !ok {
			t.Error("Expected Command attribute to be set")
		} else if int(cmd) != commands.DC_SEC_QUERY {
			t.Errorf("Expected Command to be %d (DC_SEC_QUERY), got %d", commands.DC_SEC_QUERY, cmd)
		}

		// Verify AuthCommand is set
		if authCmd, ok := ad.EvaluateAttrInt("AuthCommand"); !ok {
			t.Error("Expected AuthCommand attribute to be set")
		} else if int(authCmd) != commands.DC_NOP_WRITE {
			t.Errorf("Expected AuthCommand to be %d (DC_NOP_WRITE), got %d", commands.DC_NOP_WRITE, authCmd)
		}
	})

	t.Run("without_auth_command", func(t *testing.T) {
		config := &SecurityConfig{
			AuthMethods:    []AuthMethod{AuthFS},
			CryptoMethods:  []CryptoMethod{CryptoAES},
			Authentication: SecurityOptional,
			Encryption:     SecurityOptional,
			Integrity:      SecurityOptional,
			Command:        commands.DC_SEC_QUERY,
			// No AuthCommand set
		}

		auth := &Authenticator{
			config: config,
		}

		ad := auth.createClientSecurityAd()

		// Verify Command is set
		if cmd, ok := ad.EvaluateAttrInt("Command"); !ok {
			t.Error("Expected Command attribute to be set")
		} else if int(cmd) != commands.DC_SEC_QUERY {
			t.Errorf("Expected Command to be %d (DC_SEC_QUERY), got %d", commands.DC_SEC_QUERY, cmd)
		}

		// Verify AuthCommand is NOT set (or is undefined)
		if _, ok := ad.EvaluateAttrInt("AuthCommand"); ok {
			t.Error("Expected AuthCommand attribute to not be set when AuthCommand is 0")
		}
	})

	t.Run("noCommand_maps_to_DC_AUTHENTICATE", func(t *testing.T) {
		// An explicit NoCommand is an auth-only handshake, advertised as
		// DC_AUTHENTICATE on the wire.
		config := &SecurityConfig{
			AuthMethods:    []AuthMethod{AuthFS},
			CryptoMethods:  []CryptoMethod{CryptoAES},
			Authentication: SecurityOptional,
			Encryption:     SecurityOptional,
			Integrity:      SecurityOptional,
			Command:        NoCommand,
		}

		ad := (&Authenticator{config: config}).createClientSecurityAd()

		if cmd, ok := ad.EvaluateAttrInt("Command"); !ok {
			t.Error("Expected Command attribute to be set")
		} else if int(cmd) != commands.DC_AUTHENTICATE {
			t.Errorf("Expected NoCommand to map to %d (DC_AUTHENTICATE), got %d", commands.DC_AUTHENTICATE, cmd)
		}
		if _, ok := ad.EvaluateAttrInt("AuthCommand"); ok {
			t.Error("Expected AuthCommand attribute to not be set when not specified")
		}
	})

	t.Run("command_zero_is_sent_literally", func(t *testing.T) {
		// Command 0 is UPDATE_STARTD_AD, a real command -- it must be sent as 0,
		// not remapped to DC_AUTHENTICATE, so the server can dispatch it.
		config := &SecurityConfig{
			AuthMethods:    []AuthMethod{AuthFS},
			CryptoMethods:  []CryptoMethod{CryptoAES},
			Authentication: SecurityOptional,
			Encryption:     SecurityOptional,
			Integrity:      SecurityOptional,
			Command:        commands.UPDATE_STARTD_AD, // == 0
		}

		ad := (&Authenticator{config: config}).createClientSecurityAd()

		if cmd, ok := ad.EvaluateAttrInt("Command"); !ok {
			t.Error("Expected Command attribute to be set")
		} else if int(cmd) != commands.UPDATE_STARTD_AD {
			t.Errorf("Expected Command to be %d (UPDATE_STARTD_AD), got %d", commands.UPDATE_STARTD_AD, cmd)
		}
	})
}

// TestAuthCommandParsing tests that AuthCommand is correctly parsed from ClassAds
func TestAuthCommandParsing(t *testing.T) {
	t.Run("parse_with_auth_command", func(t *testing.T) {
		ad := classad.New()
		_ = ad.Set("Command", commands.DC_SEC_QUERY)
		_ = ad.Set("AuthCommand", commands.DC_NOP_WRITE)
		_ = ad.Set("AuthMethods", "FS")
		_ = ad.Set("CryptoMethods", "AES")
		_ = ad.Set("Authentication", "OPTIONAL")
		_ = ad.Set("Encryption", "OPTIONAL")

		auth := &Authenticator{}
		config := auth.parseServerSecurityAd(ad)

		if config.Command != commands.DC_SEC_QUERY {
			t.Errorf("Expected Command to be %d (DC_SEC_QUERY), got %d", commands.DC_SEC_QUERY, config.Command)
		}

		if config.AuthCommand != commands.DC_NOP_WRITE {
			t.Errorf("Expected AuthCommand to be %d (DC_NOP_WRITE), got %d", commands.DC_NOP_WRITE, config.AuthCommand)
		}
	})

	t.Run("parse_without_auth_command", func(t *testing.T) {
		ad := classad.New()
		_ = ad.Set("Command", commands.DC_SEC_QUERY)
		_ = ad.Set("AuthMethods", "FS")
		_ = ad.Set("CryptoMethods", "AES")

		auth := &Authenticator{}
		config := auth.parseServerSecurityAd(ad)

		if config.Command != commands.DC_SEC_QUERY {
			t.Errorf("Expected Command to be %d (DC_SEC_QUERY), got %d", commands.DC_SEC_QUERY, config.Command)
		}

		if config.AuthCommand != 0 {
			t.Errorf("Expected AuthCommand to be 0 (not set), got %d", config.AuthCommand)
		}
	})
}
