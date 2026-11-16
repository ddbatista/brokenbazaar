package agent

import (
	"reflect"
	"strings"
	"testing"
)

// M3 T4 D2, and D3 of the threat model, as one structural property in
// both builds: the session's scope never travels with the call.
//
//   - Vulnerable: the executor cannot honour a scope it is never given.
//     That is B3 2.1 planted -- the row records the scope and nothing on
//     the execution path reads it, so every session holds every tool.
//   - Hardened: the gateway re-derives scope from the session row at
//     action time (T6). A scope in the payload or the executor's config
//     would be the agent testifying to its own authority (M2-N3), and a
//     scope cached at construction is "resolved once" (SR-B3-3).
//
// If a Scope field ever appears on any of these structs, someone has
// started carrying authority alongside the call, and this fails. It has
// no build tag on purpose: the property is the same in both builds.
//
// What it pins is the INPUT, not the reads. NaiveExecutor holds a pool
// and a session id, so it could still look the scope up itself, and
// this test would not notice. The behavioural pin is end-to-end: the
// 03 least-privilege PoC (T8) must exit 0 in vulnerable mode with a
// session scoped to read_document only, and T4's live run showed the
// same shape with a delete.
func TestScopeNeverTravelsWithTheCall(t *testing.T) {
	for _, typ := range []reflect.Type{
		reflect.TypeOf(ExecutorConfig{}),
		reflect.TypeOf(SessionInfo{}),
		reflect.TypeOf(CallContext{}),
	} {
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			if strings.Contains(strings.ToLower(f.Name+" "+f.Tag.Get("json")), "scope") {
				t.Errorf("%s.%s carries scope with the call", typ.Name(), f.Name)
			}
		}
	}
}
