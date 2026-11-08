package mode

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// M2-N4: the API (and the agent) refuse to start unless the gateway reports the same
// mode. These tests pin every way that agreement can be ABSENT rather
// than merely false -- an unreachable gateway, a health body without the
// field, a non-200 -- because each of those must also refuse. An absent
// answer that reads as agreement is the failure this check exists to
// prevent, and it is the same shape as the Rego fail-open T5 caught:
// a missing operand silently removing the check.

func fakeGateway(t *testing.T, status int, body string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func probe(t *testing.T, url string, want bool) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return CheckGateway(ctx, &http.Client{Timeout: 500 * time.Millisecond}, url, want, 2, 10*time.Millisecond)
}

func TestModeAgreementAcceptsAMatchingGateway(t *testing.T) {
	for _, want := range []bool{true, false} {
		body := `{"status":"ok","hardened":false}`
		if want {
			body = `{"status":"ok","hardened":true}`
		}
		if err := probe(t, fakeGateway(t, 200, body), want); err != nil {
			t.Errorf("want=%v: %v", want, err)
		}
	}
}

func TestModeAgreementRefusesASplitBrain(t *testing.T) {
	// The state an attacker would choose: hardened API, vulnerable gateway.
	err := probe(t, fakeGateway(t, 200, `{"status":"ok","hardened":false}`), true)
	if err == nil {
		t.Fatal("a hardened API accepted a vulnerable gateway")
	}
	for _, s := range []string{"hardened", "vulnerable"} {
		if !strings.Contains(err.Error(), s) {
			t.Errorf("error %q should name both modes", err)
		}
	}
	// And the other direction: still a misconfiguration, still refused.
	if probe(t, fakeGateway(t, 200, `{"status":"ok","hardened":true}`), false) == nil {
		t.Fatal("a vulnerable API accepted a hardened gateway")
	}
}

func TestModeAgreementRefusesAnAbsentAnswer(t *testing.T) {
	cases := map[string]string{
		// The T5 gateway's body: a raw string under "mode", no boolean.
		// Pinned so an old gateway image cannot pass the new check.
		"pre-T6 body, no hardened field": `{"status":"ok","mode":"true"}`,
		"hardened is null":               `{"status":"ok","hardened":null}`,
		"hardened is a string":           `{"status":"ok","hardened":"true"}`,
		"not json":                       `ok`,
		"status not ok":                  `{"status":"starting","hardened":true}`,
	}
	for name, body := range cases {
		if err := probe(t, fakeGateway(t, 200, body), true); err == nil {
			t.Errorf("%s: accepted as agreement", name)
		}
	}
	if err := probe(t, fakeGateway(t, 503, `{"status":"ok","hardened":true}`), true); err == nil {
		t.Error("a 503 was accepted as agreement")
	}
}

func TestModeAgreementRefusesAnUnreachableOrUnconfiguredGateway(t *testing.T) {
	if err := probe(t, "", true); err == nil || !strings.Contains(err.Error(), "GATEWAY_URL") {
		t.Errorf("unset GATEWAY_URL: got %v, want a refusal naming the variable", err)
	}
	// A port nothing listens on: the probe must give up, not hang, and
	// must refuse rather than assume.
	srv := httptest.NewServer(http.NotFoundHandler())
	dead := srv.URL
	srv.Close()
	if err := probe(t, dead, true); err == nil {
		t.Error("an unreachable gateway was accepted as agreement")
	}
}

func TestModeAgreementRetriesWhileTheGatewayBoots(t *testing.T) {
	// depends_on: service_healthy orders the containers, but the probe
	// should still tolerate a gateway that answers on the second try
	// rather than racing it into a refusal.
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		if calls == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(`{"status":"ok","hardened":true}`))
	}))
	t.Cleanup(srv.Close)
	if err := probe(t, srv.URL, true); err != nil {
		t.Fatalf("second attempt should have agreed: %v", err)
	}
}
