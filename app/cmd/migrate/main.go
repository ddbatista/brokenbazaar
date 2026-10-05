// Command migrate applies migrations/*.sql, in filename order, to
// DATABASE_URL. It is intentionally not a library (no golang-migrate, no
// goose): ten lines of os.ReadDir plus one Exec per file is the whole
// feature this lab needs, and a migration framework would be a dependency
// proposal this module does not need (AGENTS.md: "do not add dependencies").
//
// Not wired into docker-compose.yml (hardened zone) or the api image
// (Dockerfile only builds ./api). Run against the host-exposed Postgres
// port instead: `make migrate`, which this is the entrypoint for.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"

	"github.com/ddbatista/brokenbazaar/app/store"
)

func main() {
	ctx := context.Background()

	// Explicit flag rather than a bare "migrations" relative path: this
	// binary's cwd is wherever `go run` was invoked from (the Makefile runs
	// it from app/), not the repo root where migrations/ actually lives. A
	// hardcoded relative path would silently resolve to the wrong directory
	// the moment anyone ran this command from somewhere else -- the same
	// "quiet instead of loud" failure shape SR-M1-1 names for JWT_SECRET.
	dir := flag.String("migrations-dir", "../migrations", "directory of .sql files to apply, in filename order")
	flag.Parse()

	// No hardcoded fallback DSN: SR-M1-1 exists because JWT_SECRET had one
	// and the default was silent. The same shape of mistake here would be a
	// migration tool that quietly points at the wrong database instead of
	// refusing to run. The Makefile sets DATABASE_URL explicitly; anyone
	// invoking this binary directly is expected to as well.
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		log.Fatal("migrate: DATABASE_URL is not set (see Makefile's `migrate` target for the local default)")
	}

	pool, err := store.Open(ctx, dbURL)
	if err != nil {
		log.Fatalf("migrate: %v", err)
	}
	defer pool.Close()

	entries, err := os.ReadDir(*dir)
	if err != nil {
		log.Fatalf("migrate: reading %s: %v", *dir, err)
	}

	var files []string
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".sql" {
			files = append(files, e.Name())
		}
	}
	sort.Strings(files) // "001_init.sql" < "002_..." by construction

	if len(files) == 0 {
		log.Fatalf("migrate: no .sql files found in %s", *dir)
	}

	for _, name := range files {
		path := filepath.Join(*dir, name)
		sql, err := os.ReadFile(path)
		if err != nil {
			log.Fatalf("migrate: reading %s: %v", path, err)
		}
		fmt.Printf("applying %s\n", path)
		if _, err := pool.Exec(ctx, string(sql)); err != nil {
			log.Fatalf("migrate: applying %s: %v", path, err)
		}
	}

	fmt.Printf("migrate: applied %d file(s)\n", len(files))
}
