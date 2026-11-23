// Package watch defines the CEDAR wire protocol for subscribing to ad changes
// in a golang collector (or any daemon backed by the classad collections engine).
//
// It is the single source of truth shared by the collector server (which streams
// events) and the htcondor client (which consumes them). The protocol is a thin
// framing over ClassAd messages:
//
//	client -> server:  command WatchAds, then a request ClassAd
//	                   [ WatchAdType = "StartdAd"; WatchCursor = "<base64>" ]
//	server -> client:  a stream of events, each an event-header ClassAd
//	                   [ WatchKind = <0..4>; WatchKey = "<key>"; WatchCursor = "<base64>" ]
//	                   immediately followed, for a WatchKind of Upsert, by the ad
//	                   ClassAd itself (a separate message).
//
// The stream continues until the client disconnects or the server's context is
// cancelled. Event kinds mirror collections.WatchKind exactly (Upsert=0 ..
// Resync=4) so a server can forward events without remapping.
package watch

import (
	"encoding/base64"
	"fmt"

	"github.com/PelicanPlatform/classad/classad"
)

// Command integers for the watch protocol. WatchCommandBase is a Pelican-specific
// allocation chosen to avoid collision with upstream HTCondor: it reclaims the
// removed TRANSFERD_BASE region (74000), which sits in a large gap between the
// grid-manager base (73000) and the credential base (81000) and which upstream
// has no live command family in. New watch verbs extend upward from the base.
const (
	WatchCommandBase = 74000

	// WatchAds subscribes to changes for one ad type in the collector.
	WatchAds = WatchCommandBase + 0
)

// Kind is the wire encoding of a watch event kind. The values match
// collections.WatchKind so the collector can forward them unchanged.
type Kind int64

const (
	// KindUpsert carries the full ad for an added or updated key; the ad follows
	// the header as a separate ClassAd message.
	KindUpsert Kind = iota
	// KindDelete signals a key was removed (no ad follows).
	KindDelete
	// KindReset tells the client to discard its state; an authoritative snapshot
	// of Upserts follows, ending at KindSynced.
	KindReset
	// KindSynced marks the end of catch-up; the client is now live. Its cursor is
	// a durable resume point.
	KindSynced
	// KindResync tells the client the live stream fell behind; it must reconnect
	// with its last persisted cursor.
	KindResync
	// KindGoingAway is a server-injected signal (not a collections.WatchKind) that
	// the server is shutting down or restarting: the client should reconnect --
	// possibly to a different collector -- with its last persisted cursor. Unlike
	// Resync (a fell-behind condition), it is sent proactively before the server
	// closes the stream, so a client can distinguish a graceful restart from a
	// drop and back off / fail over accordingly.
	KindGoingAway
)

func (k Kind) String() string {
	switch k {
	case KindUpsert:
		return "Upsert"
	case KindDelete:
		return "Delete"
	case KindReset:
		return "Reset"
	case KindSynced:
		return "Synced"
	case KindResync:
		return "Resync"
	case KindGoingAway:
		return "GoingAway"
	default:
		return fmt.Sprintf("Kind(%d)", int64(k))
	}
}

// HasAd reports whether an event of this kind is followed by an ad message.
func (k Kind) HasAd() bool { return k == KindUpsert }

// Request/event ClassAd attribute names.
const (
	AttrAdType     = "WatchAdType"     // request: which ad type to watch
	AttrConstraint = "WatchConstraint" // request: optional ClassAd match expression
	AttrKind       = "WatchKind"       // event: the Kind
	AttrKey        = "WatchKey"        // event: the ad's key (Upsert/Delete)
	AttrCursor     = "WatchCursor"     // request: resume token; event: durable cursor
)

// EncodeRequest builds the subscribe request ClassAd. constraint (a ClassAd match
// expression, e.g. `DAGManJobId == 42`) may be "" to watch all ads of the type;
// cursor may be nil for a full replay.
func EncodeRequest(adType, constraint string, cursor []byte) *classad.ClassAd {
	ad := classad.New()
	ad.InsertAttrString(AttrAdType, adType)
	if constraint != "" {
		ad.InsertAttrString(AttrConstraint, constraint)
	}
	ad.InsertAttrString(AttrCursor, encodeBytes(cursor))
	return ad
}

// DecodeRequest reads a subscribe request ClassAd. An absent constraint
// attribute yields a "" constraint, meaning no filter; a constraint attribute
// that is present but does not evaluate to a string is an error rather than
// the unfiltered firehose that silently dropping it would produce.
func DecodeRequest(ad *classad.ClassAd) (adType, constraint string, cursor []byte, err error) {
	adType, ok := ad.EvaluateAttrString(AttrAdType)
	if !ok || adType == "" {
		return "", "", nil, fmt.Errorf("watch: request missing %s", AttrAdType)
	}
	if _, present := ad.Lookup(AttrConstraint); present {
		constraint, ok = ad.EvaluateAttrString(AttrConstraint)
		if !ok {
			return "", "", nil, fmt.Errorf("watch: %s does not evaluate to a string", AttrConstraint)
		}
	}
	s, _ := ad.EvaluateAttrString(AttrCursor)
	cursor, err = decodeBytes(s)
	if err != nil {
		return "", "", nil, fmt.Errorf("watch: bad %s: %w", AttrCursor, err)
	}
	return adType, constraint, cursor, nil
}

// EncodeHeader builds an event-header ClassAd. key is nil for non-keyed events
// (Reset/Synced/Resync); cursor is nil except for Synced and live events.
func EncodeHeader(kind Kind, key, cursor []byte) *classad.ClassAd {
	ad := classad.New()
	ad.InsertAttr(AttrKind, int64(kind))
	if key != nil {
		// A collection key is opaque bytes (the collector's is a composite
		// Name\0Address with an embedded NUL), so base64 it for a clean string.
		ad.InsertAttrString(AttrKey, encodeBytes(key))
	}
	if cursor != nil {
		ad.InsertAttrString(AttrCursor, encodeBytes(cursor))
	}
	return ad
}

// DecodeHeader reads an event-header ClassAd. A returned key/cursor is nil when
// the corresponding attribute is absent. A key or cursor attribute that is
// present but does not evaluate to a string is an error: a Delete or Upsert
// with no key is not an event a caller can act on, and a dropped cursor turns
// a resume into a replay from the beginning of the stream.
func DecodeHeader(ad *classad.ClassAd) (kind Kind, key, cursor []byte, err error) {
	k, ok := ad.EvaluateAttrInt(AttrKind)
	if !ok {
		return 0, nil, nil, fmt.Errorf("watch: event missing %s", AttrKind)
	}
	if _, present := ad.Lookup(AttrKey); present {
		s, ok := ad.EvaluateAttrString(AttrKey)
		if !ok {
			return 0, nil, nil, fmt.Errorf("watch: %s does not evaluate to a string", AttrKey)
		}
		if s != "" {
			key, err = decodeBytes(s)
			if err != nil {
				return 0, nil, nil, fmt.Errorf("watch: bad %s: %w", AttrKey, err)
			}
		}
	}
	if _, present := ad.Lookup(AttrCursor); present {
		s, ok := ad.EvaluateAttrString(AttrCursor)
		if !ok {
			return 0, nil, nil, fmt.Errorf("watch: %s does not evaluate to a string", AttrCursor)
		}
		if s != "" {
			cursor, err = decodeBytes(s)
			if err != nil {
				return 0, nil, nil, fmt.Errorf("watch: bad %s: %w", AttrCursor, err)
			}
		}
	}
	return Kind(k), key, cursor, nil
}

// encodeBytes renders opaque bytes (a key or cursor) as base64 for a ClassAd
// string attribute. Empty encodes to "".
func encodeBytes(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return base64.StdEncoding.EncodeToString(b)
}

func decodeBytes(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	return base64.StdEncoding.DecodeString(s)
}
