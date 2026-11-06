// Command api is the BrokenBazaar HTTP API.
//
// BrokenBazaar is a deliberately vulnerable application, published as a
// security learning resource for security practitioners. Localhost only.
//
// M0 scope: /healthz and nothing else. Product code lands in M1, after the
// threat model is committed.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/ddbatista/brokenbazaar/app/store"
)

const listenAddr = ":8080"

// jwtSecretEnv names the signing-key variable; devJWTSecret is the committed
// development fallback used only in vulnerable mode (M1-N1).
const (
	jwtSecretEnv = "JWT_SECRET"
	devJWTSecret = "dev-secret"
)

// toolsSecretEnv names the service credential shared with the gateway
// (D5b). There is deliberately NO development fallback, unlike
// devJWTSecret: that fallback exists to plant M1-N1's weak-key finding,
// and a committed default here would plant a second one nobody asked
// for -- the agent could then read the source, present the default, and
// D5b's entire mediation claim would be false.
const toolsSecretEnv = "TOOLS_SECRET"

type healthResponse struct {
	Status   string `json:"status"`
	Service  string `json:"service"`
	Hardened bool   `json:"hardened"`
	Module   string `json:"module"`
}

func hardened() bool {
	return os.Getenv("HARDENED") == "true"
}

// loadJWTSecret returns the HMAC signing key for POST /auth/token.
//
// hardened=true (SR-B1-3): the key must come from the environment. If
// JWT_SECRET is unset the process refuses to start -- a startup failure
// naming the variable, not a request-time 401. A missing signing key is a
// misconfiguration the operator must fix before serving anything, not an
// error to discover one token at a time.
//
// hardened=false: the key falls back to the committed devJWTSecret (M1-N1 --
// the weak-key half of B1 1.2). Crucially the fallback is NOT silent
// (SR-M1-1: "loud or absent, never quiet"): it logs at WARN naming the
// variable and the consequence. Only the *strength* of the secret is
// flag-gated; the logging is not, because the leaf M1-N1 adds over the
// baseline is specifically that a real operator who typos JWT_SECRET gets a
// working stack signed with a public key and no signal that it happened.
func loadJWTSecret(hardened bool) []byte {
	secret := os.Getenv(jwtSecretEnv)
	if secret != "" {
		return []byte(secret)
	}
	if hardened {
		log.Fatalf("api: %s is not set; refusing to start in hardened mode (SR-B1-3)", jwtSecretEnv)
	}
	log.Printf("WARN: %s is not set; falling back to the committed %q secret -- "+
		"tokens are signed with a key anyone with the source can read and are therefore forgeable (M1-N1, SR-M1-1)",
		jwtSecretEnv, devJWTSecret)
	return []byte(devJWTSecret)
}

// loadToolsSecret returns the service credential the gateway presents on
// the D5b internal tool routes.
//
// Loud or absent, never quiet (SR-B1-3, SR-M1-1): unset in hardened mode
// is a startup failure naming the variable, not a route that 401s every
// caller and surfaces three layers up as "the agent could not read the
// document." The panic itself lives in registerHardened, next to the
// route declaration that needs it, so the failure message can name the
// route -- this function just reports what the environment holds.
//
// Vulnerable mode has no internal route (the agent reads in-process,
// which is the planted B5 2.1 bypass), so there is nothing to
// authenticate and nil is correct rather than a missing-config error.
func loadToolsSecret(hardened bool) []byte {
	secret := os.Getenv(toolsSecretEnv)
	if secret == "" {
		if hardened {
			log.Printf("api: %s is not set; the hardened internal tool route cannot be served (SR-B1-3, D5b)", toolsSecretEnv)
		}
		return nil
	}
	return []byte(secret)
}

// healthcheck is used by the container healthcheck so the image needs no curl.
func healthcheck() int {
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://127.0.0.1" + listenAddr + "/healthz")
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck:", err)
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, "healthcheck: status", resp.StatusCode)
		return 1
	}
	return 0
}

func healthzHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(healthResponse{
		Status:   "ok",
		Service:  "brokenbazaar-api",
		Hardened: hardened(),
		Module:   "M0",
	})
}

func main() {
	check := flag.Bool("healthcheck", false, "probe /healthz and exit")
	flag.Parse()
	if *check {
		os.Exit(healthcheck())
	}

	// The serving path needs the database; the -healthcheck path above does
	// not, which is why the pool is opened only here.
	ctx := context.Background()
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		log.Fatal("api: DATABASE_URL is not set")
	}
	pool, err := store.Open(ctx, dbURL)
	if err != nil {
		log.Fatal(err)
	}
	defer pool.Close()

	admin := store.NewAdminStore(pool)
	jwtSecret := loadJWTSecret(hardened())

	handlers := &docHandlers{admin: admin, pool: pool, hardened: hardened()}
	// SR-B1-1 (deny-by-default route registration) lands here in T5, now that
	// the token-protected document routes (D4) exist and there is something to
	// protect. The two modes register differently on purpose: hardened mode
	// routes through a declaration table that panics at startup on any route
	// missing an explicit auth: none|token (registerHardened); vulnerable mode
	// registers directly on the bare mux, the T4 pattern, with no table and no
	// such panic. /healthz and /auth/token keep their T4 behaviour in both.
	//
	// T4 note: registerHardened now BUILDS and OWNS its mux, returning a
	// handler whose ServeMux is unreachable. That closes M1's T9 rot
	// finding -- the panic only ever covered routes already in the table,
	// so a handler registered straight onto the mux bypassed SR-B1-1
	// entirely. There is no longer a mux in scope here to register onto.
	var handler http.Handler
	if hardened() {
		handler = registerHardened(handlers, admin, jwtSecret, loadToolsSecret(true))
	} else {
		// Vulnerable mode keeps the bare mux on purpose: no table, no
		// auth declaration, no panic-on-missing. That contrast is the
		// SR-B1-1 lesson, and it is the deliverable.
		mux := http.NewServeMux()
		registerVulnerable(mux, handlers, admin, jwtSecret)
		handler = mux
	}

	srv := &http.Server{
		Addr:              listenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("brokenbazaar api listening on %s (HARDENED=%v)", listenAddr, hardened())
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
