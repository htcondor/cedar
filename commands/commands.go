// Package commands provides HTCondor command constants and utilities
//
// This package enumerates all known HTCondor commands based on the official
// condor_commands.h header file. It provides constants for command integers
// and utilities to work with them.
package commands

// HTCondor command base values
const (
	// Base values for different command categories
	SCHED_VERS                = 400   // Scheduler commands base
	QMGMT_BASE                = 1110  // Queue management commands base
	DC_BASE                   = 60000 // Daemon Core commands base
	HAD_COMMANDS_BASE         = 700   // HAD commands base
	REPLICATION_COMMANDS_BASE = 800   // Replication commands base
	CA_AUTH_CMD_BASE          = 1000  // ClassAd auth commands base
	CA_CMD_BASE               = 1200  // ClassAd commands base
	FILETRANSFER_BASE         = 61000 // File transfer commands base
	DCSHADOW_BASE             = 71000 // Shadow commands base
	DCGRIDMANAGER_BASE        = 73000 // Grid manager commands base
	CREDD_BASE                = 75000 // Credential daemon commands base
)

// Scheduler Commands (SCHED_VERS + offset)
const (
	CONTINUE_CLAIM              = SCHED_VERS + 1   // Continue foreign job
	SUSPEND_CLAIM               = SCHED_VERS + 2   // Suspend foreign job
	DEACTIVATE_CLAIM            = SCHED_VERS + 3   // Deactivate claim
	ACTIVATE_CLAIM_PROTOCOL     = SCHED_VERS + 4   // Activate claim protocol
	NEGOTIATE                   = SCHED_VERS + 16  // Negotiation command
	SEND_JOB_INFO               = SCHED_VERS + 17  // Send job info in negotiation
	NO_MORE_JOBS                = SCHED_VERS + 18  // No more jobs in negotiation
	JOB_INFO                    = SCHED_VERS + 19  // Job info in negotiation
	RESCHEDULE                  = SCHED_VERS + 21  // Reschedule
	END_NEGOTIATE               = SCHED_VERS + 25  // End negotiation
	REJECTED                    = SCHED_VERS + 26  // Rejected
	X_EVENT_NOTIFICATION        = SCHED_VERS + 27  // Event notification
	GET_HISTORY                 = SCHED_VERS + 29  // Get history
	MATCH_INFO                  = SCHED_VERS + 40  // Match info
	ALIVE                       = SCHED_VERS + 41  // Alive check
	REQUEST_CLAIM               = SCHED_VERS + 42  // Request claim
	RELEASE_CLAIM               = SCHED_VERS + 43  // Release claim
	ACTIVATE_CLAIM              = SCHED_VERS + 44  // Activate claim
	VACATE_ALL_CLAIMS           = SCHED_VERS + 47  // Vacate all claims
	GIVE_STATE                  = SCHED_VERS + 48  // Give state
	SET_PRIORITY                = SCHED_VERS + 49  // Set priority
	GET_PRIORITY                = SCHED_VERS + 51  // Get priority
	DAEMONS_OFF_FLEX            = SCHED_VERS + 52  // Daemons off with payload
	RESTART                     = SCHED_VERS + 53  // Restart
	DAEMONS_OFF                 = SCHED_VERS + 54  // Daemons off
	DAEMONS_ON                  = SCHED_VERS + 55  // Daemons on
	MASTER_OFF                  = SCHED_VERS + 56  // Master off
	CONFIG_VAL                  = SCHED_VERS + 57  // Config value
	RESET_USAGE                 = SCHED_VERS + 58  // Reset usage
	SET_PRIORITYFACTOR          = SCHED_VERS + 59  // Set priority factor
	RESET_ALL_USAGE             = SCHED_VERS + 60  // Reset all usage
	DELETE_USER                 = SCHED_VERS + 82  // Delete user
	VACATE_CLAIM                = SCHED_VERS + 65  // Vacate claim
	DAEMON_OFF                  = SCHED_VERS + 67  // Daemon off
	DAEMON_OFF_FAST             = SCHED_VERS + 68  // Daemon off fast
	DAEMON_ON                   = SCHED_VERS + 69  // Daemon on
	GIVE_TOTALS_CLASSAD         = SCHED_VERS + 70  // Give totals ClassAd
	PERMISSION_AND_AD           = SCHED_VERS + 72  // Permission and ad
	VACATE_ALL_FAST             = SCHED_VERS + 74  // Vacate all fast
	VACATE_CLAIM_FAST           = SCHED_VERS + 75  // Vacate claim fast
	REJECTED_WITH_REASON        = SCHED_VERS + 76  // Rejected with reason
	START_AGENT                 = SCHED_VERS + 77  // Start agent
	ACT_ON_JOBS                 = SCHED_VERS + 78  // Act on jobs
	STORE_CRED                  = SCHED_VERS + 79  // Store credential
	SPOOL_JOB_FILES             = SCHED_VERS + 80  // Spool job files
	DAEMON_OFF_PEACEFUL         = SCHED_VERS + 83  // Daemon off peaceful
	DAEMONS_OFF_PEACEFUL        = SCHED_VERS + 84  // Daemons off peaceful
	RESTART_PEACEFUL            = SCHED_VERS + 85  // Restart peaceful
	TRANSFER_DATA               = SCHED_VERS + 86  // Transfer data
	UPDATE_GSI_CRED             = SCHED_VERS + 87  // Update GSI credential
	SPOOL_JOB_FILES_WITH_PERMS  = SCHED_VERS + 88  // Spool job files with perms
	TRANSFER_DATA_WITH_PERMS    = SCHED_VERS + 89  // Transfer data with perms
	CHILD_ON                    = SCHED_VERS + 90  // Child on
	CHILD_OFF                   = SCHED_VERS + 91  // Child off
	CHILD_OFF_FAST              = SCHED_VERS + 92  // Child off fast
	SET_ACCUMUSAGE              = SCHED_VERS + 94  // Set accumulated usage
	SET_BEGINTIME               = SCHED_VERS + 95  // Set begin time
	SET_LASTTIME                = SCHED_VERS + 96  // Set last time
	STORE_POOL_CRED             = SCHED_VERS + 97  // Store pool credential
	DELEGATE_GSI_CRED_SCHEDD    = SCHED_VERS + 99  // Delegate GSI cred to schedd
	DELEGATE_GSI_CRED_STARTER   = SCHED_VERS + 100 // Delegate GSI cred to starter
	DELEGATE_GSI_CRED_STARTD    = SCHED_VERS + 101 // Delegate GSI cred to startd
	REQUEST_SANDBOX_LOCATION    = SCHED_VERS + 102 // Request sandbox location
	VM_UNIV_GAHP_ERROR          = SCHED_VERS + 103 // VM universe GAHP error
	VM_UNIV_VMPID               = SCHED_VERS + 104 // VM universe VM PID
	VM_UNIV_GUEST_IP            = SCHED_VERS + 105 // VM universe guest IP
	VM_UNIV_GUEST_MAC           = SCHED_VERS + 106 // VM universe guest MAC
	TRANSFER_QUEUE_REQUEST      = SCHED_VERS + 107 // Transfer queue request
	SET_SHUTDOWN_PROGRAM        = SCHED_VERS + 108 // Set shutdown program
	GET_JOB_CONNECT_INFO        = SCHED_VERS + 109 // Get job connect info
	RECYCLE_SHADOW              = SCHED_VERS + 110 // Recycle shadow
	CLEAR_DIRTY_JOB_ATTRS       = SCHED_VERS + 111 // Clear dirty job attrs
	DRAIN_JOBS                  = SCHED_VERS + 112 // Drain jobs
	CANCEL_DRAIN_JOBS           = SCHED_VERS + 113 // Cancel drain jobs
	GET_PRIORITY_ROLLUP         = SCHED_VERS + 114 // Get priority rollup
	QUERY_SCHEDD_HISTORY        = SCHED_VERS + 115 // Query schedd history
	QUERY_JOB_ADS               = SCHED_VERS + 116 // Query job ads
	SEND_RESOURCE_REQUEST_LIST  = SCHED_VERS + 118 // Send resource request list
	QUERY_JOB_ADS_WITH_AUTH     = SCHED_VERS + 119 // Query job ads with auth
	FETCH_PROXY_DELEGATION      = SCHED_VERS + 120 // Fetch proxy delegation
	REASSIGN_SLOT               = SCHED_VERS + 121 // Reassign slot
	COALESCE_SLOTS              = SCHED_VERS + 122 // Coalesce slots
	COLLECTOR_TOKEN_REQUEST     = SCHED_VERS + 123 // Collector token request
	GET_CEILING                 = SCHED_VERS + 124 // Get ceiling
	SET_CEILING                 = SCHED_VERS + 125 // Set ceiling
	EXPORT_JOBS                 = SCHED_VERS + 126 // Export jobs
	IMPORT_EXPORTED_JOB_RESULTS = SCHED_VERS + 127 // Import exported job results
	UNEXPORT_JOBS               = SCHED_VERS + 128 // Unexport jobs
	GET_FLOOR                   = SCHED_VERS + 129 // Get floor
	SET_FLOOR                   = SCHED_VERS + 130 // Set floor
	DIRECT_ATTACH               = SCHED_VERS + 131 // Direct attach

	// Schedd UserRec commands (140-149 reserved)
	QUERY_USERREC_ADS = SCHED_VERS + 140 // Query user record ads
	ENABLE_USERREC    = SCHED_VERS + 141 // Enable user record
	DISABLE_USERREC   = SCHED_VERS + 142 // Disable user record
	EDIT_USERREC      = SCHED_VERS + 143 // Edit user record
	RESET_USERREC     = SCHED_VERS + 144 // Reset user record
	DELETE_USERREC    = SCHED_VERS + 149 // Delete user record
	GET_CONTACT_INFO  = SCHED_VERS + 150 // Get contact info
)

// Daemon Core Commands (DC_BASE + offset)
const (
	DC_RAISESIGNAL                = DC_BASE + 0  // Raise signal
	DC_CONFIG_PERSIST             = DC_BASE + 2  // Config persist
	DC_CONFIG_RUNTIME             = DC_BASE + 3  // Config runtime
	DC_RECONFIG                   = DC_BASE + 4  // Reconfig
	DC_OFF_GRACEFUL               = DC_BASE + 5  // Off graceful
	DC_OFF_FAST                   = DC_BASE + 6  // Off fast
	DC_CONFIG_VAL                 = DC_BASE + 7  // Config value
	DC_CHILDALIVE                 = DC_BASE + 8  // Child alive
	DC_SERVICEWAITPIDS            = DC_BASE + 9  // Service wait PIDs
	DC_AUTHENTICATE               = DC_BASE + 10 // Authenticate
	DC_NOP                        = DC_BASE + 11 // No operation
	DC_RECONFIG_FULL              = DC_BASE + 12 // Full reconfig
	DC_FETCH_LOG                  = DC_BASE + 13 // Fetch log
	DC_INVALIDATE_KEY             = DC_BASE + 14 // Invalidate key
	DC_OFF_PEACEFUL               = DC_BASE + 15 // Off peaceful
	DC_SET_PEACEFUL_SHUTDOWN      = DC_BASE + 16 // Set peaceful shutdown
	DC_TIME_OFFSET                = DC_BASE + 17 // Time offset
	DC_PURGE_LOG                  = DC_BASE + 18 // Purge log
	DC_NOP_READ                   = DC_BASE + 20 // NOP read
	DC_NOP_WRITE                  = DC_BASE + 21 // NOP write
	DC_NOP_NEGOTIATOR             = DC_BASE + 22 // NOP negotiator
	DC_NOP_ADMINISTRATOR          = DC_BASE + 23 // NOP administrator
	DC_NOP_OWNER                  = DC_BASE + 24 // NOP owner
	DC_NOP_CONFIG                 = DC_BASE + 25 // NOP config
	DC_NOP_DAEMON                 = DC_BASE + 26 // NOP daemon
	DC_NOP_ADVERTISE_STARTD       = DC_BASE + 27 // NOP advertise startd
	DC_NOP_ADVERTISE_SCHEDD       = DC_BASE + 28 // NOP advertise schedd
	DC_NOP_ADVERTISE_MASTER       = DC_BASE + 29 // NOP advertise master
	DC_SEC_QUERY                  = DC_BASE + 40 // Security query
	DC_SET_FORCE_SHUTDOWN         = DC_BASE + 41 // Set force shutdown
	DC_OFF_FORCE                  = DC_BASE + 42 // Off force
	DC_SET_READY                  = DC_BASE + 43 // Set ready
	DC_QUERY_READY                = DC_BASE + 44 // Query ready
	DC_QUERY_INSTANCE             = DC_BASE + 45 // Query instance
	DC_GET_SESSION_TOKEN          = DC_BASE + 46 // Get session token
	DC_START_TOKEN_REQUEST        = DC_BASE + 47 // Start token request
	DC_FINISH_TOKEN_REQUEST       = DC_BASE + 48 // Finish token request
	DC_LIST_TOKEN_REQUEST         = DC_BASE + 49 // List token request
	DC_APPROVE_TOKEN_REQUEST      = DC_BASE + 50 // Approve token request
	DC_AUTO_APPROVE_TOKEN_REQUEST = DC_BASE + 51 // Auto approve token request
	DC_EXCHANGE_SCITOKEN          = DC_BASE + 52 // Exchange SciToken
)

// Collector Commands (starting from 0)
const (
	UPDATE_STARTD_AD                = 0  // Update startd ad
	UPDATE_SCHEDD_AD                = 1  // Update schedd ad
	UPDATE_MASTER_AD                = 2  // Update master ad
	UPDATE_CKPT_SRVR_AD             = 4  // Update checkpoint server ad
	QUERY_STARTD_ADS                = 5  // Query startd ads - MOST COMMON
	QUERY_SCHEDD_ADS                = 6  // Query schedd ads
	QUERY_MASTER_ADS                = 7  // Query master ads
	QUERY_CKPT_SRVR_ADS             = 9  // Query checkpoint server ads
	QUERY_STARTD_PVT_ADS            = 10 // Query startd private ads
	UPDATE_SUBMITTOR_AD             = 11 // Update submitter ad
	QUERY_SUBMITTOR_ADS             = 12 // Query submitter ads
	INVALIDATE_STARTD_ADS           = 13 // Invalidate startd ads
	INVALIDATE_SCHEDD_ADS           = 14 // Invalidate schedd ads
	INVALIDATE_MASTER_ADS           = 15 // Invalidate master ads
	INVALIDATE_CKPT_SRVR_ADS        = 17 // Invalidate checkpoint server ads
	INVALIDATE_SUBMITTOR_ADS        = 18 // Invalidate submitter ads
	UPDATE_COLLECTOR_AD             = 19 // Update collector ad
	QUERY_COLLECTOR_ADS             = 20 // Query collector ads
	INVALIDATE_COLLECTOR_ADS        = 21 // Invalidate collector ads
	QUERY_HIST_STARTD               = 22 // Query startd history
	QUERY_HIST_STARTD_LIST          = 23 // Query startd history list
	QUERY_HIST_SUBMITTOR            = 24 // Query submitter history
	QUERY_HIST_SUBMITTOR_LIST       = 25 // Query submitter history list
	QUERY_HIST_GROUPS               = 26 // Query groups history
	QUERY_HIST_GROUPS_LIST          = 27 // Query groups history list
	QUERY_HIST_SUBMITTORGROUPS      = 28 // Query submitter groups history
	QUERY_HIST_SUBMITTORGROUPS_LIST = 29 // Query submitter groups history list
	QUERY_HIST_CKPTSRVR             = 30 // Query checkpoint server history
	QUERY_HIST_CKPTSRVR_LIST        = 31 // Query checkpoint server history list
	UPDATE_LICENSE_AD               = 42 // Update license ad
	QUERY_LICENSE_ADS               = 43 // Query license ads
	INVALIDATE_LICENSE_ADS          = 44 // Invalidate license ads
	UPDATE_STORAGE_AD               = 45 // Update storage ad
	QUERY_STORAGE_ADS               = 46 // Query storage ads
	INVALIDATE_STORAGE_ADS          = 47 // Invalidate storage ads
	QUERY_ANY_ADS                   = 48 // Query any ads
	UPDATE_NEGOTIATOR_AD            = 49 // Update negotiator ad
	QUERY_NEGOTIATOR_ADS            = 50 // Query negotiator ads
	INVALIDATE_NEGOTIATOR_ADS       = 51 // Invalidate negotiator ads
	QUERY_MULTIPLE_ADS              = 53 // Query multiple ads
	QUERY_MULTIPLE_PVT_ADS          = 54 // Query multiple private ads
	UPDATE_HAD_AD                   = 55 // Update HAD ad
	QUERY_HAD_ADS                   = 56 // Query HAD ads
	INVALIDATE_HAD_ADS              = 57 // Invalidate HAD ads
	UPDATE_AD_GENERIC               = 58 // Update generic ad
	INVALIDATE_ADS_GENERIC          = 59 // Invalidate generic ads
	UPDATE_STARTD_AD_WITH_ACK       = 60 // Update startd ad with ack
	CCB_REGISTER                    = 67 // CCB register
	CCB_REQUEST                     = 68 // CCB request
	CCB_REVERSE_CONNECT             = 69 // CCB reverse connect
	UPDATE_GRID_AD                  = 70 // Update grid ad
	QUERY_GRID_ADS                  = 71 // Query grid ads
	INVALIDATE_GRID_ADS             = 72 // Invalidate grid ads
	MERGE_STARTD_AD                 = 73 // Merge startd ad
	QUERY_GENERIC_ADS               = 74 // Query generic ads
	SHARED_PORT_CONNECT             = 75 // Shared port connect
	SHARED_PORT_PASS_SOCK           = 76 // Shared port pass socket
	UPDATE_ACCOUNTING_AD            = 77 // Update accounting ad
	QUERY_ACCOUNTING_ADS            = 78 // Query accounting ads
	INVALIDATE_ACCOUNTING_ADS       = 79 // Invalidate accounting ads
	UPDATE_OWN_SUBMITTOR_AD         = 80 // Update own submitter ad
	IMPERSONATION_TOKEN_REQUEST     = 81 // Impersonation token request
	CCB_PROXY_CONNECT               = 82 // CCB outbound proxy connect (tunneling)
	CCB_GET_TUNNEL_ADDRESS          = 83 // master->CCB: fetch derived tunnel address (tunneling)
)

// Queue Management Commands
const (
	QMGMT_READ_CMD  = QMGMT_BASE + 1 // Queue management read
	QMGMT_WRITE_CMD = QMGMT_BASE + 2 // Queue management write
)

// ClassAd Commands ("CA commands")
//
// A CA command is not dispatched by its own command integer. The integer put on
// the wire is one of the two entry points below -- CA_AUTH_CMD when the client
// forces authentication, CA_CMD when it does not -- and the receiving daemon
// then reads the Command *string* out of the request ClassAd to decide which
// verb to run (getCmdFromReliSock, condor_utils/classad_command_util.cpp). The
// per-verb constants below therefore exist to name that string, not to be sent.
const (
	CA_AUTH_CMD = CA_AUTH_CMD_BASE + 0 // Authenticated ClassAd-command entry point (1000)
	CA_CMD      = CA_CMD_BASE + 0      // Unauthenticated ClassAd-command entry point (1200)

	CA_UPDATE_MACHINE_AD = CA_AUTH_CMD_BASE + 9 // Merge attributes into the startd machine ad (1009)
)

// HAD Commands
const (
	HAD_ALIVE_CMD               = HAD_COMMANDS_BASE + 0 // HAD alive
	HAD_SEND_ID_CMD             = HAD_COMMANDS_BASE + 1 // HAD send ID
	HAD_BEFORE_PASSIVE_STATE    = HAD_COMMANDS_BASE + 3 // HAD before passive state
	HAD_AFTER_ELECTION_STATE    = HAD_COMMANDS_BASE + 4 // HAD after election state
	HAD_AFTER_LEADER_STATE      = HAD_COMMANDS_BASE + 5 // HAD after leader state
	HAD_IN_LEADER_STATE         = HAD_COMMANDS_BASE + 6 // HAD in leader state
	HAD_CONTROLLEE_TOGGLE_STATE = HAD_COMMANDS_BASE + 7 // HAD controllee toggle state
)

// Shadow Commands
const (
	MPI_START_COMRADE = DCSHADOW_BASE + 2 // MPI start comrade
	GIVE_MATCHES      = DCSHADOW_BASE + 3 // Give matches
	UPDATE_JOBAD      = DCSHADOW_BASE + 5 // Update job ad
)

// Other Commands
const (
	SQUAWK               = 72000                  // Squawk (condor_squawk tool)
	GRIDMAN_CHECK_LEASES = DCGRIDMANAGER_BASE + 0 // Grid manager check leases
)

// File Transfer Commands
const (
	FILETRANS_UPLOAD   = FILETRANSFER_BASE + 0 // File transfer upload
	FILETRANS_DOWNLOAD = FILETRANSFER_BASE + 1 // File transfer download
)

// Credential Daemon Commands
const (
	CREDD_GET_CRED    = CREDD_BASE + 1   // Get credential
	CREDD_STORE_CRED  = CREDD_BASE + 2   // Store credential
	CREDD_REMOVE_CRED = CREDD_BASE + 3   // Remove credential
	CREDD_QUERY_CRED  = CREDD_BASE + 4   // Query credential
	CREDD_REFRESH_ALL = CREDD_BASE + 10  // Refresh all credentials
	CREDD_CHECK_CREDS = CREDD_BASE + 98  // Check credentials
	CREDD_GET_PASSWD  = CREDD_BASE + 99  // Get password (Win32 only)
	CREDD_NOP         = CREDD_BASE + 100 // NOP (Win32 only)
)

// CommandType represents the different types of HTCondor commands
type CommandType int

const (
	SchedulerCommand CommandType = iota
	DaemonCoreCommand
	CollectorCommand
	QueueManagementCommand
	HADCommand
	ShadowCommand
	GridManagerCommand
	FileTransferCommand
	CredentialCommand
	OtherCommand
	ClassAdCommand
)

// CommandInfo holds information about a command
type CommandInfo struct {
	Name        string      // Human-readable name
	Code        int         // Command integer code
	Type        CommandType // Category of command
	Description string      // Brief description
}

// commandTable maps command codes to their information
var commandTable = map[int]CommandInfo{
	// Commonly used collector commands
	QUERY_STARTD_ADS: {
		Name:        "QUERY_STARTD_ADS",
		Code:        QUERY_STARTD_ADS,
		Type:        CollectorCommand,
		Description: "Query startd (slot) advertisements",
	},
	QUERY_SCHEDD_ADS: {
		Name:        "QUERY_SCHEDD_ADS",
		Code:        QUERY_SCHEDD_ADS,
		Type:        CollectorCommand,
		Description: "Query schedd advertisements",
	},
	QUERY_MASTER_ADS: {
		Name:        "QUERY_MASTER_ADS",
		Code:        QUERY_MASTER_ADS,
		Type:        CollectorCommand,
		Description: "Query master advertisements",
	},
	QUERY_NEGOTIATOR_ADS: {
		Name:        "QUERY_NEGOTIATOR_ADS",
		Code:        QUERY_NEGOTIATOR_ADS,
		Type:        CollectorCommand,
		Description: "Query negotiator advertisements",
	},
	QUERY_COLLECTOR_ADS: {
		Name:        "QUERY_COLLECTOR_ADS",
		Code:        QUERY_COLLECTOR_ADS,
		Type:        CollectorCommand,
		Description: "Query collector advertisements",
	},
	QUERY_SUBMITTOR_ADS: {
		Name:        "QUERY_SUBMITTOR_ADS",
		Code:        QUERY_SUBMITTOR_ADS,
		Type:        CollectorCommand,
		Description: "Query submitter advertisements",
	},

	// Schedd job management commands
	QUERY_JOB_ADS: {
		Name:        "QUERY_JOB_ADS",
		Code:        QUERY_JOB_ADS,
		Type:        SchedulerCommand,
		Description: "Query job advertisements",
	},
	QUERY_JOB_ADS_WITH_AUTH: {
		Name:        "QUERY_JOB_ADS_WITH_AUTH",
		Code:        QUERY_JOB_ADS_WITH_AUTH,
		Type:        SchedulerCommand,
		Description: "Query job advertisements with authentication",
	},
	ACT_ON_JOBS: {
		Name:        "ACT_ON_JOBS",
		Code:        ACT_ON_JOBS,
		Type:        SchedulerCommand,
		Description: "Act on jobs (hold, release, remove)",
	},
	QUERY_SCHEDD_HISTORY: {
		Name:        "QUERY_SCHEDD_HISTORY",
		Code:        QUERY_SCHEDD_HISTORY,
		Type:        SchedulerCommand,
		Description: "Query schedd job history",
	},

	// Authentication command
	DC_AUTHENTICATE: {
		Name:        "DC_AUTHENTICATE",
		Code:        DC_AUTHENTICATE,
		Type:        DaemonCoreCommand,
		Description: "Perform authentication handshake",
	},

	// Negotiation commands
	NEGOTIATE: {
		Name:        "NEGOTIATE",
		Code:        NEGOTIATE,
		Type:        SchedulerCommand,
		Description: "Start negotiation cycle",
	},
	SEND_JOB_INFO: {
		Name:        "SEND_JOB_INFO",
		Code:        SEND_JOB_INFO,
		Type:        SchedulerCommand,
		Description: "Send job information during negotiation",
	},

	// Management commands
	RESCHEDULE: {
		Name:        "RESCHEDULE",
		Code:        RESCHEDULE,
		Type:        SchedulerCommand,
		Description: "Trigger reschedule cycle",
	},
	RESTART: {
		Name:        "RESTART",
		Code:        RESTART,
		Type:        SchedulerCommand,
		Description: "Restart daemon",
	},
	CONFIG_VAL: {
		Name:        "CONFIG_VAL",
		Code:        CONFIG_VAL,
		Type:        SchedulerCommand,
		Description: "Get configuration value",
	},

	// ClassAd commands
	CA_AUTH_CMD: {
		Name:        "CA_AUTH_CMD",
		Code:        CA_AUTH_CMD,
		Type:        ClassAdCommand,
		Description: "Authenticated ClassAd-command entry point",
	},
	CA_CMD: {
		Name:        "CA_CMD",
		Code:        CA_CMD,
		Type:        ClassAdCommand,
		Description: "Unauthenticated ClassAd-command entry point",
	},
	CA_UPDATE_MACHINE_AD: {
		Name:        "CA_UPDATE_MACHINE_AD",
		Code:        CA_UPDATE_MACHINE_AD,
		Type:        ClassAdCommand,
		Description: "Merge attributes into the startd machine ad",
	},
}

// GetCommandInfo returns information about a command code
func GetCommandInfo(code int) (CommandInfo, bool) {
	info, exists := commandTable[code]
	return info, exists
}

// GetCommandName returns the name of a command code
func GetCommandName(code int) string {
	if info, exists := commandTable[code]; exists {
		return info.Name
	}
	return ""
}

// GetCommandCode returns the code for a command name
func GetCommandCode(name string) (int, bool) {
	for _, info := range commandTable {
		if info.Name == name {
			return info.Code, true
		}
	}
	return 0, false
}

// IsValidCommand checks if a command code is known
func IsValidCommand(code int) bool {
	_, exists := commandTable[code]
	return exists
}

// GetCommandsByType returns all commands of a specific type
func GetCommandsByType(cmdType CommandType) []CommandInfo {
	var commands []CommandInfo
	for _, info := range commandTable {
		if info.Type == cmdType {
			commands = append(commands, info)
		}
	}
	return commands
}

// GetAllCommands returns all known commands
func GetAllCommands() []CommandInfo {
	var commands []CommandInfo
	for _, info := range commandTable {
		commands = append(commands, info)
	}
	return commands
}
