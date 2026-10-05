// Command seed populates three orgs, one user per role per org, and
// documents per org.
//
// SR-M1-2: this seed is a security control, not a fixture. It creates
// Org/User/Membership rows through AdminStore (direct SQL is fine there --
// see store/admin.go's doc comment for why), but every Document row is
// created through store.ForOrg(pool, orgID), never with direct SQL. That is
// what makes SR-B2-1 ("no code path can obtain a database handle without an
// org context") true as written instead of true-except-at-bootstrap
// (M1-N2). Schema DDL (migrate) may bypass the store; rows in a
// tenant-scoped table may not, including the very first rows.
package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/ddbatista/brokenbazaar/app/store"
)

type seedOrg struct {
	name string
	// one user per role, in a fixed order so printed output and
	// attacks/NN-*/expected.json can both rely on it.
	users []seedUser
}

type seedUser struct {
	email       string
	displayName string
	role        store.Role
}

// password is the same for every seeded user -- it is a lab, not a product,
// and R-M1-4 already declares "credentials are seeded, static and shared"
// as accepted non-coverage. Printed at the end so a reader can log in
// without reading this file.
const seedPassword = "bazaar-dev-only"

func seedData() []seedOrg {
	return []seedOrg{
		{
			name: "Acme Corp",
			users: []seedUser{
				{"admin@acme.example", "Acme Admin", store.RoleAdmin},
				{"member@acme.example", "Acme Member", store.RoleMember},
				{"viewer@acme.example", "Acme Viewer", store.RoleViewer},
			},
		},
		{
			name: "Globex",
			users: []seedUser{
				{"admin@globex.example", "Globex Admin", store.RoleAdmin},
				{"member@globex.example", "Globex Member", store.RoleMember},
				{"viewer@globex.example", "Globex Viewer", store.RoleViewer},
			},
		},
		{
			name: "Initech",
			users: []seedUser{
				{"admin@initech.example", "Initech Admin", store.RoleAdmin},
				{"member@initech.example", "Initech Member", store.RoleMember},
				{"viewer@initech.example", "Initech Viewer", store.RoleViewer},
			},
		},
	}
}

func main() {
	ctx := context.Background()

	// See migrate/main.go: no hardcoded fallback DSN, same SR-M1-1 reasoning.
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		log.Fatal("seed: DATABASE_URL is not set (see Makefile's `seed` target for the local default)")
	}

	pool, err := store.Open(ctx, dbURL)
	if err != nil {
		log.Fatalf("seed: %v", err)
	}
	defer pool.Close()

	passwordHash, err := store.HashPassword(seedPassword)
	if err != nil {
		log.Fatalf("seed: hashing seed password: %v", err)
	}

	admin := store.NewAdminStore(pool)

	for _, so := range seedData() {
		org, err := admin.CreateOrg(ctx, so.name)
		if err != nil {
			log.Fatalf("seed: %v", err)
		}
		fmt.Printf("org %-10s %s\n", org.Name, org.ID)

		var adminUserID string
		for _, su := range so.users {
			u, err := admin.CreateUser(ctx, su.email, su.displayName, passwordHash)
			if err != nil {
				log.Fatalf("seed: %v", err)
			}
			if err := admin.AddMembership(ctx, org.ID, u.ID, su.role); err != nil {
				log.Fatalf("seed: %v", err)
			}
			fmt.Printf("  user  %-28s %-8s %s\n", u.Email, su.role, u.ID)
			if su.role == store.RoleAdmin {
				adminUserID = u.ID
			}
		}

		// Documents go through ForOrg -- SR-M1-2. The title carries the org
		// name so attacks/01-cross-tenant-read's expected.json can assert on
		// a stable, greppable string instead of a status code.
		docStore := store.ForOrg(pool, org.ID)
		doc, err := docStore.Create(ctx, store.Document{
			Title:     fmt.Sprintf("%s — confidential Q3 plan", org.Name),
			Body:      fmt.Sprintf("This document belongs to %s and must not be readable by any other org.", org.Name),
			CreatedBy: adminUserID,
		})
		if err != nil {
			log.Fatalf("seed: %v", err)
		}
		fmt.Printf("  doc   %-40s %s\n", doc.Title, doc.ID)
	}

	fmt.Printf("\nseed: done. every seeded user's password is %q (R-M1-4, lab only).\n", seedPassword)
}
