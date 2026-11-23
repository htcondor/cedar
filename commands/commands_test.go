package commands

import "testing"

func TestCommandConstants(t *testing.T) {
	// Test that common commands have expected values
	expectedCommands := map[string]int{
		"QUERY_STARTD_ADS": 5,
		"QUERY_SCHEDD_ADS": 6,
		"QUERY_JOB_ADS":    516,   // SCHED_VERS (400) + 116
		"DC_AUTHENTICATE":  60010, // DC_BASE (60000) + 10
	}

	for name, expectedCode := range expectedCommands {
		switch name {
		case "QUERY_STARTD_ADS":
			if QUERY_STARTD_ADS != expectedCode {
				t.Errorf("Expected %s to be %d, got %d", name, expectedCode, QUERY_STARTD_ADS)
			}
		case "QUERY_SCHEDD_ADS":
			if QUERY_SCHEDD_ADS != expectedCode {
				t.Errorf("Expected %s to be %d, got %d", name, expectedCode, QUERY_SCHEDD_ADS)
			}
		case "QUERY_JOB_ADS":
			if QUERY_JOB_ADS != expectedCode {
				t.Errorf("Expected %s to be %d, got %d", name, expectedCode, QUERY_JOB_ADS)
			}
		case "DC_AUTHENTICATE":
			if DC_AUTHENTICATE != expectedCode {
				t.Errorf("Expected %s to be %d, got %d", name, expectedCode, DC_AUTHENTICATE)
			}
		}
	}
}

func TestCommandInfo(t *testing.T) {
	// Test getting command info
	info, exists := GetCommandInfo(QUERY_STARTD_ADS)
	if !exists {
		t.Error("QUERY_STARTD_ADS should exist in command table")
	}
	if info.Name != "QUERY_STARTD_ADS" {
		t.Errorf("Expected name QUERY_STARTD_ADS, got %s", info.Name)
	}
	if info.Type != CollectorCommand {
		t.Errorf("Expected type CollectorCommand, got %v", info.Type)
	}

	// Test non-existent command
	_, exists = GetCommandInfo(99999)
	if exists {
		t.Error("Command 99999 should not exist")
	}
}

func TestGetCommandName(t *testing.T) {
	name := GetCommandName(QUERY_STARTD_ADS)
	if name != "QUERY_STARTD_ADS" {
		t.Errorf("Expected QUERY_STARTD_ADS, got %s", name)
	}

	// Test unknown command
	name = GetCommandName(99999)
	if name != "" {
		t.Errorf("Expected empty string for unknown command, got %s", name)
	}
}

func TestGetCommandCode(t *testing.T) {
	code, exists := GetCommandCode("QUERY_STARTD_ADS")
	if !exists {
		t.Error("QUERY_STARTD_ADS should exist")
	}
	if code != QUERY_STARTD_ADS {
		t.Errorf("Expected %d, got %d", QUERY_STARTD_ADS, code)
	}

	// Test unknown command
	_, exists = GetCommandCode("UNKNOWN_COMMAND")
	if exists {
		t.Error("UNKNOWN_COMMAND should not exist")
	}
}

func TestIsValidCommand(t *testing.T) {
	if !IsValidCommand(QUERY_STARTD_ADS) {
		t.Error("QUERY_STARTD_ADS should be valid")
	}

	if IsValidCommand(99999) {
		t.Error("Command 99999 should not be valid")
	}
}

func TestGetCommandsByType(t *testing.T) {
	collectors := GetCommandsByType(CollectorCommand)
	if len(collectors) == 0 {
		t.Error("Should have collector commands")
	}

	// Verify all returned commands are collector commands
	for _, cmd := range collectors {
		if cmd.Type != CollectorCommand {
			t.Errorf("Expected CollectorCommand, got %v", cmd.Type)
		}
	}
}

func TestCreddCommandConstants(t *testing.T) {
	// Absolute wire values, per condor_commands.h in the C++ implementation.
	// These are asserted as literals rather than as CREDD_BASE + offset so a
	// wrong base cannot pass.
	tests := []struct {
		name string
		got  int
		want int
	}{
		{"CREDD_BASE", CREDD_BASE, 81000},
		{"CREDD_STORE_CRED", CREDD_STORE_CRED, 81000},
		{"CREDD_GET_CRED", CREDD_GET_CRED, 81001},
		{"CREDD_REMOVE_CRED", CREDD_REMOVE_CRED, 81002},
		{"CREDD_QUERY_CRED", CREDD_QUERY_CRED, 81003},
		{"CREDD_GET_TOKEN", CREDD_GET_TOKEN, 81004},
		{"CREDD_REFRESH_ALL", CREDD_REFRESH_ALL, 81020},
		{"CREDD_CHECK_CREDS", CREDD_CHECK_CREDS, 81030},
		{"CREDD_GET_PASSWD", CREDD_GET_PASSWD, 81099},
		{"CREDD_NOP", CREDD_NOP, 81100},
	}

	for _, tt := range tests {
		if tt.got != tt.want {
			t.Errorf("Expected %s to be %d, got %d", tt.name, tt.want, tt.got)
		}
	}
}
