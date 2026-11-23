package watch

import (
	"bytes"
	"testing"

	"github.com/PelicanPlatform/classad/classad"
)

func TestRequestRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		adType     string
		constraint string
		cursor     []byte
	}{
		{"StartdAd", "", nil},
		{"StartdAd", "", []byte{0x01, 0x02, 0xff, 0x00}},
		{"ScheddAd", `DAGManJobId == 42`, []byte("cursor-bytes")},
		{"JobAd", `Owner == "alice" && ClusterId == 7`, nil},
	} {
		ad := EncodeRequest(tc.adType, tc.constraint, tc.cursor)
		gotType, gotConstraint, gotCursor, err := DecodeRequest(ad)
		if err != nil {
			t.Fatalf("DecodeRequest(%q): %v", tc.adType, err)
		}
		if gotType != tc.adType {
			t.Errorf("adType: got %q want %q", gotType, tc.adType)
		}
		if gotConstraint != tc.constraint {
			t.Errorf("constraint: got %q want %q", gotConstraint, tc.constraint)
		}
		if !bytes.Equal(gotCursor, tc.cursor) {
			t.Errorf("cursor: got %x want %x", gotCursor, tc.cursor)
		}
	}
}

func TestHeaderRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		kind   Kind
		key    []byte
		cursor []byte
	}{
		{KindUpsert, []byte("slot1@host"), nil},
		{KindDelete, []byte("slot2@host"), nil},
		{KindReset, nil, nil},
		{KindSynced, nil, []byte{0x00, 0x01, 0x02}},
		{KindResync, nil, nil},
		{KindUpsert, []byte("k"), []byte("live-cursor")},
	} {
		ad := EncodeHeader(tc.kind, tc.key, tc.cursor)
		gotKind, gotKey, gotCursor, err := DecodeHeader(ad)
		if err != nil {
			t.Fatalf("DecodeHeader(%v): %v", tc.kind, err)
		}
		if gotKind != tc.kind {
			t.Errorf("kind: got %v want %v", gotKind, tc.kind)
		}
		if !bytes.Equal(gotKey, tc.key) {
			t.Errorf("key: got %q want %q", gotKey, tc.key)
		}
		if !bytes.Equal(gotCursor, tc.cursor) {
			t.Errorf("cursor: got %x want %x", gotCursor, tc.cursor)
		}
		if tc.kind.HasAd() != (tc.kind == KindUpsert) {
			t.Errorf("HasAd wrong for %v", tc.kind)
		}
	}
}

// TestDecodeRequestNonStringConstraint checks that a constraint attribute of
// the wrong type is rejected. Silently dropping it would turn a filtered
// subscription into an unfiltered one, which no caller can detect.
func TestDecodeRequestNonStringConstraint(t *testing.T) {
	for _, tc := range []struct {
		name   string
		insert func(*classad.ClassAd)
	}{
		{"int", func(ad *classad.ClassAd) { ad.InsertAttr(AttrConstraint, 42) }},
		{"bool", func(ad *classad.ClassAd) { ad.InsertAttrBool(AttrConstraint, true) }},
		{"undefined", func(ad *classad.ClassAd) {
			expr, err := classad.ParseExpr("NoSuchAttribute")
			if err != nil {
				t.Fatalf("ParseExpr: %v", err)
			}
			ad.InsertExpr(AttrConstraint, expr)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ad := classad.New()
			ad.InsertAttrString(AttrAdType, "StartdAd")
			tc.insert(ad)

			_, constraint, _, err := DecodeRequest(ad)
			if err == nil {
				t.Fatalf("DecodeRequest accepted a non-string %s, returning constraint %q",
					AttrConstraint, constraint)
			}
		})
	}
}

// TestDecodeRequestAbsentConstraint pins the documented meaning of an absent
// constraint: no filter, no error. The fix for a non-string constraint must
// not catch this case.
func TestDecodeRequestAbsentConstraint(t *testing.T) {
	ad := classad.New()
	ad.InsertAttrString(AttrAdType, "StartdAd")

	adType, constraint, cursor, err := DecodeRequest(ad)
	if err != nil {
		t.Fatalf("DecodeRequest: %v", err)
	}
	if adType != "StartdAd" {
		t.Errorf("adType: got %q want %q", adType, "StartdAd")
	}
	if constraint != "" {
		t.Errorf("constraint: got %q want \"\"", constraint)
	}
	if cursor != nil {
		t.Errorf("cursor: got %x want nil", cursor)
	}
}

// TestDecodeHeaderNonStringKey checks that a key attribute of the wrong type
// is rejected rather than yielding a keyed event with a nil key and no error.
func TestDecodeHeaderNonStringKey(t *testing.T) {
	for _, tc := range []struct {
		name   string
		insert func(*classad.ClassAd)
	}{
		{"int", func(ad *classad.ClassAd) { ad.InsertAttr(AttrKey, 42) }},
		{"bool", func(ad *classad.ClassAd) { ad.InsertAttrBool(AttrKey, true) }},
		{"undefined", func(ad *classad.ClassAd) {
			expr, err := classad.ParseExpr("NoSuchAttribute")
			if err != nil {
				t.Fatalf("ParseExpr: %v", err)
			}
			ad.InsertExpr(AttrKey, expr)
		}},
	} {
		for _, kind := range []Kind{KindUpsert, KindDelete} {
			t.Run(tc.name+"_"+kind.String(), func(t *testing.T) {
				ad := classad.New()
				ad.InsertAttr(AttrKind, int64(kind))
				tc.insert(ad)

				_, key, _, err := DecodeHeader(ad)
				if err == nil {
					t.Fatalf("DecodeHeader accepted a non-string %s, returning key %q",
						AttrKey, key)
				}
			})
		}
	}
}

// TestDecodeHeaderAbsentKey pins the documented meaning of an absent key: nil,
// no error, as the non-keyed event kinds rely on.
func TestDecodeHeaderAbsentKey(t *testing.T) {
	for _, kind := range []Kind{KindReset, KindSynced, KindResync, KindGoingAway} {
		ad := classad.New()
		ad.InsertAttr(AttrKind, int64(kind))

		gotKind, key, cursor, err := DecodeHeader(ad)
		if err != nil {
			t.Fatalf("DecodeHeader(%v): %v", kind, err)
		}
		if gotKind != kind {
			t.Errorf("kind: got %v want %v", gotKind, kind)
		}
		if key != nil {
			t.Errorf("key for %v: got %q want nil", kind, key)
		}
		if cursor != nil {
			t.Errorf("cursor for %v: got %x want nil", kind, cursor)
		}
	}
}

// A cursor attribute that is present but not a string must be an error. It was
// silently discarded, which is worse than a dropped key: a nil cursor means
// "start from the beginning", so a subscriber resuming a stream got a full
// replay instead of the events it had not seen, with nothing to indicate why.
func TestDecodeHeaderNonStringCursor(t *testing.T) {
	for _, tc := range []struct {
		name   string
		insert func(*classad.ClassAd)
	}{
		{"int", func(ad *classad.ClassAd) { ad.InsertAttr(AttrCursor, 42) }},
		{"bool", func(ad *classad.ClassAd) { ad.InsertAttrBool(AttrCursor, true) }},
		{"undefined", func(ad *classad.ClassAd) {
			expr, err := classad.ParseExpr("NoSuchAttribute")
			if err != nil {
				t.Fatalf("ParseExpr: %v", err)
			}
			ad.InsertExpr(AttrCursor, expr)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ad := classad.New()
			ad.InsertAttr(AttrKind, int64(KindSynced))
			tc.insert(ad)

			_, _, cursor, err := DecodeHeader(ad)
			if err == nil {
				t.Fatalf("DecodeHeader accepted a non-string %s, returning cursor %q",
					AttrCursor, cursor)
			}
		})
	}
}

// An absent cursor keeps its documented meaning: nil, no error. A subscriber
// starting fresh sends no cursor, so this must not become an error.
func TestDecodeHeaderAbsentCursor(t *testing.T) {
	ad := classad.New()
	ad.InsertAttr(AttrKind, int64(KindSynced))

	_, _, cursor, err := DecodeHeader(ad)
	if err != nil {
		t.Fatalf("DecodeHeader with no cursor: %v", err)
	}
	if cursor != nil {
		t.Errorf("cursor = %q, want nil for an absent attribute", cursor)
	}
}

// A well-formed cursor still round-trips, so the type check cannot be
// satisfied by rejecting cursors outright.
func TestDecodeHeaderValidCursorRoundTrips(t *testing.T) {
	want := []byte{0xde, 0xad, 0xbe, 0xef}
	ad := classad.New()
	ad.InsertAttr(AttrKind, int64(KindSynced))
	ad.InsertAttrString(AttrCursor, encodeBytes(want))

	_, _, cursor, err := DecodeHeader(ad)
	if err != nil {
		t.Fatalf("DecodeHeader: %v", err)
	}
	if string(cursor) != string(want) {
		t.Errorf("cursor = %x, want %x", cursor, want)
	}
}
