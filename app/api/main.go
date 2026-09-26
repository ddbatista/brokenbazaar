// Command api is the BrokenBazaar HTTP API.
//
// BrokenBazaar is a deliberately vulnerable application, published as a
// security learning resource for security practitioners. Localhost only.
//
// M0 scope: /healthz and nothing else. Product code lands in M1, after the
// threat model is committed.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
)

const listenAddr = ":8080"

type healthResponse struct {
	Status   string `json:"status"`
	Service  string `json:"service"`
	Hardened bool   `json:"hardened"`
	Module   string `json:"module"`
}

func hardened() bool {
	return os.Getenv("HARDENED") == "true"
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

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", healthzHandler)

	srv := &http.Server{
		Addr:              listenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("brokenbazaar api listening on %s (HARDENED=%v)", listenAddr, hardened())
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
