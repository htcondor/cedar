package ccb

import (
	"reflect"
	"testing"

	"github.com/htcondor/cedar/security"
)

// A SecurityConfig field that nobody classified is the bug this table exists to
// prevent: the broker leg starts from the caller's config for the TARGET, so a
// new field travels to the broker with target-aimed meaning unless someone
// decided otherwise. ServerName and DelegatedCredential were each that mistake.
//
// Go gives no compile error for an added struct field, so this is the gate.
func TestBrokerFieldDispositionsAreExhaustive(t *testing.T) {
	typ := reflect.TypeOf(security.SecurityConfig{})

	seen := map[string]bool{}
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if f.PkgPath != "" {
			continue // unexported: brokerConfig cannot reach it
		}
		seen[f.Name] = true
		if _, ok := brokerFieldDispositions[f.Name]; !ok {
			t.Errorf("security.SecurityConfig.%s (%s) has no broker-leg disposition.\n"+
				"Decide what the broker should see and add it to brokerFieldDispositions in brokerconfig.go:\n"+
				"  carried  -- describes this host, means the same to a broker\n"+
				"  reAimed  -- names the peer or the work; set it in brokerConfig\n"+
				"  cleared  -- target-only; zero it in brokerConfig\n"+
				"  refused  -- makes a broker leg impermissible; refuse in dialBrokerAuthOnce",
				f.Name, f.Type)
		}
	}

	for name := range brokerFieldDispositions {
		if !seen[name] {
			t.Errorf("brokerFieldDispositions names %q, which security.SecurityConfig no longer has", name)
		}
	}
}

// Every field's disposition must match what brokerConfig actually does, so the
// table stays documentation of the code rather than of an intention.
func TestBrokerConfigMatchesItsDispositions(t *testing.T) {
	const (
		brokerAddr = "broker.example.org:9618"
		command    = CommandRequest
	)

	// A config with every field distinguishably non-zero, so "carried" is
	// visible as equality and "cleared" as a zero.
	target := nonZeroSecurityConfig(t)
	got := brokerConfig(target, brokerAddr, command)

	gotV := reflect.ValueOf(*got)
	wantV := reflect.ValueOf(*target)
	typ := gotV.Type()

	for i := 0; i < typ.NumField(); i++ {
		name := typ.Field(i).Name
		if typ.Field(i).PkgPath != "" {
			continue
		}
		g, w := gotV.Field(i), wantV.Field(i)

		switch brokerFieldDispositions[name] {
		case dispositionCarried, dispositionRefused:
			// Refused configs never reach brokerConfig, so the field is
			// simply copied; the refusal is dialBrokerAuthOnce's and has
			// its own tests.
			if !sameFieldValue(g, w) {
				t.Errorf("%s is classified carried but brokerConfig changed it: %v -> %v", name, w, g)
			}
		case dispositionCleared:
			if !g.IsZero() {
				t.Errorf("%s is classified cleared but brokerConfig left %v", name, g)
			}
		case dispositionReAimed:
			if sameFieldValue(g, w) {
				t.Errorf("%s is classified reAimed but brokerConfig left the target's value %v", name, w)
			}
			if g.IsZero() {
				t.Errorf("%s is classified reAimed but brokerConfig zeroed it instead of re-aiming", name)
			}
		}
	}

	// And the re-aimed values are the broker's, not merely different.
	if got.PeerName != brokerAddr {
		t.Errorf("PeerName = %q, want the broker address %q", got.PeerName, brokerAddr)
	}
	if got.Command != command {
		t.Errorf("Command = %d, want the CCB command %d", got.Command, command)
	}

	// The caller's config is the caller's: brokerConfig must copy it.
	if target.PeerName == brokerAddr || target.SessionID == "" || target.ServerName == "" {
		t.Error("brokerConfig mutated the caller's config instead of copying it")
	}
}

// sameFieldValue compares two fields of the same struct field index. Funcs,
// maps and pointers are compared by identity, which is what "carried" means for
// them -- the broker leg must get the caller's own hook, not a copy.
func sameFieldValue(a, b reflect.Value) bool {
	switch a.Kind() {
	case reflect.Func, reflect.Map, reflect.Pointer, reflect.Slice, reflect.Chan, reflect.UnsafePointer:
		return a.Pointer() == b.Pointer()
	default:
		return reflect.DeepEqual(a.Interface(), b.Interface())
	}
}

// nonZeroSecurityConfig fills every exported field with a distinguishable
// non-zero value by reflection, so the test does not have to be updated for a
// field whose disposition is already recorded.
func nonZeroSecurityConfig(t *testing.T) *security.SecurityConfig {
	t.Helper()

	cfg := &security.SecurityConfig{}
	v := reflect.ValueOf(cfg).Elem()
	typ := v.Type()

	for i := 0; i < typ.NumField(); i++ {
		if typ.Field(i).PkgPath != "" {
			continue
		}
		f := v.Field(i)
		switch f.Kind() {
		case reflect.String:
			f.SetString("target-" + typ.Field(i).Name)
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			f.SetInt(int64(7 + i))
		case reflect.Bool:
			f.SetBool(true)
		case reflect.Slice:
			f.Set(reflect.MakeSlice(f.Type(), 1, 1))
		case reflect.Map:
			f.Set(reflect.MakeMap(f.Type()))
		case reflect.Pointer:
			f.Set(reflect.New(f.Type().Elem()))
		case reflect.Func:
			f.Set(reflect.MakeFunc(f.Type(), func(args []reflect.Value) []reflect.Value {
				out := make([]reflect.Value, f.Type().NumOut())
				for j := range out {
					out[j] = reflect.Zero(f.Type().Out(j))
				}
				return out
			}))
		case reflect.Interface:
			// Left nil: no stand-in value exists for an arbitrary interface,
			// and a carried interface field is covered by identity equality
			// of two nils.
		default:
			t.Fatalf("no non-zero value for %s (%s); teach nonZeroSecurityConfig about it",
				typ.Field(i).Name, f.Kind())
		}
	}
	return cfg
}
