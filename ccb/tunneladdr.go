package ccb

import (
	"context"
	"fmt"
	"time"

	"github.com/htcondor/cedar/security"
)

// GetTunnelAddress asks a CCB broker (an inside CCB) for its derived tunnel
// address -- the "<outside>#<inside_id>" contact it obtained by registering
// upstream (§4.5). A master uses this in the off-host CCB deployment (Model 2) to
// learn the CCB_ADDRESS to inject into child daemons, when it cannot read the
// CCB's address file locally. The command is authenticated (DAEMON on the
// server); subsys names the requesting subsystem (debugging only).
func GetTunnelAddress(ctx context.Context, brokerAddr string, sec *security.SecurityConfig, subsys string) (string, error) {
	if sec == nil {
		return "", fmt.Errorf("ccb: GetTunnelAddress requires a Security config")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	conn, s, _, err := dialBrokerAuthCmd(ctx, brokerAddr, sec, CommandGetTunnelAddress, brokerDial{})
	if err != nil {
		return "", err
	}
	defer func() { _ = conn.Close() }()

	if err := WriteControlAd(ctx, s, NewAd(map[string]any{AttrSubsys: subsys})); err != nil {
		return "", err
	}
	reply, err := ReadControlAd(ctx, s)
	if err != nil {
		return "", err
	}
	if result, _ := AdBool(reply, AttrResult); !result {
		return "", fmt.Errorf("ccb: broker %s has no tunnel address: %s", brokerAddr, AdString(reply, AttrErrorString))
	}
	addr := AdString(reply, AttrCCBAddress)
	if addr == "" {
		return "", fmt.Errorf("ccb: broker %s returned an empty tunnel address", brokerAddr)
	}
	return addr, nil
}
