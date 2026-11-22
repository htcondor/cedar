package ccb

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/PelicanPlatform/classad/classad"
	"github.com/htcondor/cedar/security"
	"github.com/htcondor/cedar/stream"
)

// InboundMeta carries the routing/audit fields from the reverse-connect request
// (forwarded by the requesting broker) to the ConnHandler. For a recursive inbound
// tunnel (Model 1), a non-empty Route means the handler is an intermediate CCB and
// must set up the next hop and relay rather than serve a command locally; Route is
// the space-separated remaining downstream CCBIDs after this hop. OriginalRequester
// and PriorHop are the audit trail (see the CCBRoute/CCBOriginalRequester/CCBPriorHop
// attributes).
type InboundMeta struct {
	Route             string
	OriginalRequester string
	PriorHop          string
}

// ConnHandler is called with each inbound reverse connection a Listener
// accepts on behalf of the registered daemon. By the time it is called the
// reverse-connect hello has been sent; the connection is now an ordinary
// inbound CEDAR command socket on which the caller is the server (the remote
// requester will drive DC_AUTHENTICATE). The handler owns the conn and must
// close it. meta carries any tunnel route/audit forwarded by the broker.
type ConnHandler func(conn net.Conn, meta InboundMeta)

// ListenerConfig configures a CCB Listener (a daemon registering itself with
// one or more brokers so private peers can reach it).
type ListenerConfig struct {
	// BrokerAddrs are the CCB broker addresses ("host:port", brackets
	// optional) to register with. A daemon in a pool with multiple CCB
	// servers registers with all of them, and the union of the assigned
	// contacts (see Contacts) forms the ccbid list in the daemon's sinful.
	BrokerAddrs []string

	// BrokerAddr is a convenience for the single-broker case. If set, it is
	// appended to BrokerAddrs.
	BrokerAddr string

	// Security authenticates registration to the broker. Its Command is
	// overridden with CCB_REGISTER. Required.
	Security *security.SecurityConfig

	// Handler receives each reverse-connected inbound connection. Required.
	Handler ConnHandler

	// Name identifies this daemon to the broker (debugging only).
	Name string

	// HeartbeatInterval is how often to send ALIVE (default 1200s, min 30s).
	HeartbeatInterval time.Duration

	// ReconnectInterval is how long to wait before re-registering after a
	// broker connection drops (default 60s).
	ReconnectInterval time.Duration

	// DialTimeout bounds reverse-connect dials to requesters (default 30s).
	DialTimeout time.Duration

	// Dial, when set, reaches the broker(s) over a non-default carrier (see
	// BrokerDialer) instead of TCP -- used by an inside CCB whose upstream link
	// is a tunnel. It is used for BOTH the persistent registration dial and the
	// reverse-connect dials the broker asks for (in streaming mode those target
	// the broker's own address, i.e. the same carrier peer). nil ⇒ default
	// TCP/shared-port. A carrier is point-to-point, so this is only sensible with
	// a single broker in the list.
	Dial BrokerDialer

	// DialControl, if set, is installed as net.Dialer.Control on the
	// reverse-connect dials: the TCP connections, including one to a shared
	// port, to the address a CCB_REQUEST names as MyAddress. That address
	// comes from whoever asked the broker to reach this daemon, so this is
	// where to refuse destinations (an SSRF guard). It sees the resolved
	// "ip:port"; returning an error fails that request, which is reported to
	// the broker. It does not apply to the registration dial to the
	// configured brokers, nor when Dial supplies a carrier.
	DialControl func(network, address string, c syscall.RawConn) error
}

// SplitBrokerList splits a CCB broker list as written in configuration (e.g.
// the value of CCB_ADDRESS), which is separated by commas and/or whitespace,
// into individual broker addresses.
func SplitBrokerList(s string) []string {
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n'
	})
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}

// Listener maintains a persistent registration with one or more CCB brokers and
// services reverse-connect requests from any of them. Each broker is handled by
// an independent registration (its own connection, heartbeat, and reconnect
// loop), so one broker going down does not affect the others.
type Listener struct {
	cfg  ListenerConfig
	regs []*brokerReg
}

// NewListener creates a Listener for all configured brokers.
func NewListener(cfg ListenerConfig) *Listener {
	if cfg.HeartbeatInterval == 0 {
		cfg.HeartbeatInterval = 1200 * time.Second
	}
	if cfg.HeartbeatInterval < 30*time.Second {
		cfg.HeartbeatInterval = 30 * time.Second
	}
	if cfg.ReconnectInterval == 0 {
		cfg.ReconnectInterval = 60 * time.Second
	}
	if cfg.DialTimeout == 0 {
		cfg.DialTimeout = 30 * time.Second
	}

	l := &Listener{cfg: cfg}
	addrs := append([]string{}, cfg.BrokerAddrs...)
	if cfg.BrokerAddr != "" {
		addrs = append(addrs, cfg.BrokerAddr)
	}
	for _, addr := range addrs {
		l.regs = append(l.regs, &brokerReg{addr: addr, cfg: &l.cfg})
	}
	return l
}

// Run registers with every broker and services requests until ctx is
// cancelled, reconnecting (preserving each ccbid via its reconnect cookie) on
// failure. It returns after all broker loops have stopped.
func (l *Listener) Run(ctx context.Context) error {
	if len(l.regs) == 0 {
		return fmt.Errorf("ccb: listener has no broker addresses")
	}
	var wg sync.WaitGroup
	for _, r := range l.regs {
		wg.Add(1)
		go func(r *brokerReg) {
			defer wg.Done()
			r.run(ctx)
		}(r)
	}
	wg.Wait()
	return ctx.Err()
}

// Contacts returns the CCB contact strings ("addr#id") currently assigned by
// the brokers this listener is registered with, one per registered broker.
// Together they are the ccbid list to advertise in the daemon's sinful. Brokers
// that are not currently registered are omitted.
func (l *Listener) Contacts() []string {
	out := make([]string, 0, len(l.regs))
	for _, r := range l.regs {
		if c := r.getContact(); c != "" {
			out = append(out, c)
		}
	}
	return out
}

// ContactList returns Contacts joined by spaces, i.e. the value to use for the
// "ccbid" parameter of a sinful string.
func (l *Listener) ContactList() string {
	return strings.Join(l.Contacts(), " ")
}

// Contact returns a single assigned contact (the first registered broker's),
// for convenience in the common single-broker case. Empty until registered.
func (l *Listener) Contact() string {
	if cs := l.Contacts(); len(cs) > 0 {
		return cs[0]
	}
	return ""
}

// NumRegistered returns how many of the configured brokers are currently
// registered.
func (l *Listener) NumRegistered() int {
	return len(l.Contacts())
}

// BrokerSupportsStreaming reports whether any currently-registered broker
// advertised streaming support. Returns false if no broker is registered.
func (l *Listener) BrokerSupportsStreaming() bool {
	// Streaming is possible as long as *any* registered broker supports it: a
	// requester can reach this daemon by streaming through that broker.
	for _, r := range l.regs {
		r.mu.Lock()
		reg, streaming := r.registered, r.brokerStreaming
		r.mu.Unlock()
		if reg && streaming {
			return true
		}
	}
	return false
}

// brokerReg is the per-broker registration state and loop.
type brokerReg struct {
	addr string
	cfg  *ListenerConfig

	mu              sync.Mutex
	writeMu         sync.Mutex // serializes writes to the broker stream
	stream          *stream.Stream
	conn            net.Conn
	contact         string // "addr#id" assigned by this broker
	cookie          string // reconnect cookie
	brokerStreaming bool
	registered      bool
}

func (r *brokerReg) getContact() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.registered {
		return ""
	}
	return r.contact
}

// run registers with this broker and services it until ctx is cancelled,
// reconnecting on failure.
func (r *brokerReg) run(ctx context.Context) {
	attempt := 0 // consecutive failed/dropped rounds; reset on a good registration
	for {
		if ctx.Err() != nil {
			return
		}
		if err := r.register(ctx); err != nil {
			attempt++
			if !sleepCtx(ctx, r.reconnectDelay(attempt)) {
				return
			}
			continue
		}
		attempt = 0
		r.serve(ctx) // returns when the broker connection drops
		r.closeConn()
		attempt++
		if !sleepCtx(ctx, r.reconnectDelay(attempt)) {
			return
		}
	}
}

// reconnectDelay returns the jittered delay before the Nth consecutive
// reconnect attempt. The ceiling ramps up over the first few attempts -- 1/4,
// then 1/2, then the full ReconnectInterval -- so a daemon recovers quickly
// from a brief blip but backs off if a broker stays down. The actual delay is
// uniformly random in [0, ceiling) so that many daemons whose shared broker
// bounced do not reconnect in lockstep and stampede it.
func (r *brokerReg) reconnectDelay(attempt int) time.Duration {
	full := r.cfg.ReconnectInterval
	var ceiling time.Duration
	switch {
	case attempt <= 1:
		ceiling = full / 4
	case attempt == 2:
		ceiling = full / 2
	default:
		ceiling = full
	}
	if ceiling <= 0 {
		return 0
	}
	return time.Duration(rand.Int63n(int64(ceiling)))
}

func (r *brokerReg) register(ctx context.Context) error {
	// dialBroker transparently handles a CCB that is behind a shared port; a
	// configured carrier (r.cfg.Dial) reaches the broker over a tunnel instead.
	//
	// The shared helper retries once on a stale cached session, which matters
	// more here than anywhere else: a listener re-registers precisely when the
	// broker has restarted, and a restarted broker is exactly the peer that no
	// longer has the session this side cached.
	cfg := *r.cfg.Security
	s, _, err := dialBrokerAuthenticated(ctx, r.addr, "ccb-listener", &cfg, CommandRegister, brokerDial{carrier: r.cfg.Dial})
	if err != nil {
		return err
	}
	conn := s.GetConnection()

	reg := map[string]any{
		AttrCommand: CommandRegister,
		AttrName:    r.cfg.Name,
	}
	r.mu.Lock()
	if r.contact != "" && r.cookie != "" {
		// Reconnect: try to preserve our ccbid.
		reg[AttrCCBID] = r.contact
		reg[AttrClaimID] = r.cookie
	}
	r.mu.Unlock()

	if err := WriteControlAd(ctx, s, NewAd(reg)); err != nil {
		_ = conn.Close()
		return err
	}
	reply, err := ReadControlAd(ctx, s)
	if err != nil {
		_ = conn.Close()
		return err
	}
	contact := AdString(reply, AttrCCBID)
	if contact == "" {
		_ = conn.Close()
		return fmt.Errorf("ccb: registration reply from %s missing CCBID", r.addr)
	}
	streaming, _ := AdBool(reply, AttrCCBStreaming)

	r.mu.Lock()
	r.conn = conn
	r.stream = s
	r.contact = contact
	r.cookie = AdString(reply, AttrClaimID)
	r.brokerStreaming = streaming
	r.registered = true
	r.mu.Unlock()
	return nil
}

// serve reads control messages from the broker until the connection drops.
func (r *brokerReg) serve(ctx context.Context) {
	hbCtx, hbCancel := context.WithCancel(ctx)
	defer hbCancel()
	go r.heartbeatLoop(hbCtx)

	for {
		if ctx.Err() != nil {
			return
		}
		ad, err := ReadControlAd(ctx, r.stream)
		if err != nil {
			return
		}
		cmd, _ := AdInt(ad, AttrCommand)
		switch int(cmd) {
		case CommandRequest:
			go r.handleRequest(ctx, ad)
		case CommandAlive:
			// heartbeat from broker; nothing to do.
		default:
			// ignore unexpected messages.
		}
	}
}

func (r *brokerReg) heartbeatLoop(ctx context.Context) {
	t := time.NewTicker(r.cfg.HeartbeatInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			ad := NewAd(map[string]any{AttrCommand: CommandAlive})
			if err := r.writeToBroker(ctx, ad); err != nil {
				return
			}
		}
	}
}

// handleRequest performs a reverse connection to the requester named in the
// CCB_REQUEST and hands it to the user Handler, then reports the result.
func (r *brokerReg) handleRequest(ctx context.Context, ad *classad.ClassAd) {
	myAddr := AdString(ad, AttrMyAddress)
	connectID := AdString(ad, AttrClaimID)
	requestID := AdString(ad, AttrRequestID)

	result := NewAd(map[string]any{
		AttrClaimID:   connectID,
		AttrRequestID: requestID,
		AttrMyAddress: myAddr,
	})

	// A proxied request goes back to the broker we registered through: the first
	// hop out, which we know from our own configuration. The address the broker
	// named is its own and tells us nothing, and a registrant reached through a
	// relay cannot route to it -- the only address it can dial is r.addr.
	if proxied, ok := AdBool(ad, AttrCCBProxyMode); ok && proxied {
		myAddr = r.addr
	}

	dialCtx, cancel := context.WithTimeout(ctx, r.cfg.DialTimeout)
	defer cancel()
	// The reverse-connect target is usually the requester's own (directly
	// dialable) address, but in streaming/proxy mode it is the broker's own
	// address so the broker can splice us to the requester. When that broker is
	// behind a shared port, myAddr is a shared-port sinful, so dial through the
	// shared-port-aware helper rather than a plain TCP dial.
	s, err := dialBrokerWith(dialCtx, myAddr, "ccb-reverse-connect", brokerDial{carrier: r.cfg.Dial, control: r.cfg.DialControl})
	if err != nil {
		_ = result.Set(AttrResult, false)
		_ = result.Set(AttrErrorString, "failed to connect: "+err.Error())
		_ = r.writeToBroker(ctx, result)
		return
	}
	conn := s.GetConnection()

	if err := WriteReverseConnect(dialCtx, s, connectID, requestID, myAddr); err != nil {
		_ = conn.Close()
		_ = result.Set(AttrResult, false)
		_ = result.Set(AttrErrorString, "failed to send reverse-connect: "+err.Error())
		_ = r.writeToBroker(ctx, result)
		return
	}

	// Hand the now-inbound command socket to the user, along with any tunnel
	// route/audit the broker forwarded (a non-empty Route means the user is an
	// intermediate CCB and should recurse rather than serve a command). They own
	// the conn.
	if r.cfg.Handler != nil {
		meta := InboundMeta{
			Route:             AdString(ad, AttrCCBRoute),
			OriginalRequester: AdString(ad, AttrCCBOriginalRequester),
			PriorHop:          AdString(ad, AttrCCBPriorHop),
		}
		go r.cfg.Handler(conn, meta)
	} else {
		_ = conn.Close()
	}

	_ = result.Set(AttrResult, true)
	_ = r.writeToBroker(ctx, result)
}

func (r *brokerReg) writeToBroker(ctx context.Context, ad *classad.ClassAd) error {
	r.mu.Lock()
	s := r.stream
	r.mu.Unlock()
	if s == nil {
		return fmt.Errorf("ccb: not connected to broker %s", r.addr)
	}
	r.writeMu.Lock()
	defer r.writeMu.Unlock()
	return WriteControlAd(ctx, s, ad)
}

func (r *brokerReg) closeConn() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.conn != nil {
		_ = r.conn.Close()
		r.conn = nil
		r.stream = nil
	}
	r.registered = false
}

// sleepCtx waits for d or until ctx is cancelled; returns false if cancelled.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
