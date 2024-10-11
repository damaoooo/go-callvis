package main

import (
	"database/sql"
	"fmt"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func TestGetNewData(t *testing.T) {
	res, res2 := GetNewData()
	fmt.Printf("%v\n", res)
	fmt.Printf("%v\n", res2)
}

func TestInitDB(t *testing.T) {
	InitDB()
}

func setupTestDB() *sql.DB {
	db, _ := sql.Open("sqlite3", ":memory:")
	CreateDB(db)
	return db
}

func TestGetGOIDsByCVE_ReturnsCorrectGOIDs(t *testing.T) {
	db := setupTestDB()
	defer func(db *sql.DB) {
		err := db.Close()
		if err != nil {

		}
	}(db)

	// Insert test data
	_, err := db.Exec("INSERT INTO cve (go_id, cve_id) VALUES (?, ?)", "GO-2021-0001", "CVE-2021-0001")
	if err != nil {
		t.Fatalf("Failed to insert test data: %v", err)
	}

	gdb := &GoVulnerableDatabase{db: db}
	found, goIDs := gdb.GetGOIDsByCVE("cve-2021-0001")

	if !found {
		t.Errorf("Expected to find CVE-2021-0001, but did not")
	}
	if len(goIDs) != 1 || goIDs[0] != "GO-2021-0001" {
		t.Errorf("Expected GO-2021-0001, got %v", goIDs)
	}
}

func TestGetGOIDsByCVE_ReturnsEmptyForNonExistentCVE(t *testing.T) {
	db := setupTestDB()
	defer func(db *sql.DB) {
		err := db.Close()
		if err != nil {

		}
	}(db)

	gdb := &GoVulnerableDatabase{db: db}
	found, goIDs := gdb.GetGOIDsByCVE("cve-2021-9999")

	if found {
		t.Errorf("Expected not to find CVE-2021-9999, but did")
	}
	if len(goIDs) != 0 {
		t.Errorf("Expected empty result, got %v", goIDs)
	}
}

func TestFindVulnerableFunction_ReturnsCorrectFunctions(t *testing.T) {
	// Mock HTTP response and database setup
	// This part is omitted for brevity, but you would use a library like httptest to mock the HTTP response

	// Example test case
	gdb := &GoVulnerableDatabase{}
	vulnerableFunctions := gdb.GetVulnerableFunctionsByGOID("GO-2024-2660", "CVE-2021-0001")

	if len(*vulnerableFunctions) == 0 {
		t.Errorf("Expected to find vulnerable functions, but did not")
	}
}

func TestFindVulnerableFunction_ReturnsEmptyForNonExistentGoID(t *testing.T) {
	// Mock HTTP response and database setup
	// This part is omitted for brevity, but you would use a library like httptest to mock the HTTP response

	// Example test case
	gdb := &GoVulnerableDatabase{}
	vulnerableFunctions := gdb.GetVulnerableFunctionsByGOID("GO-2024-2664", "CVE-2021-0001")

	if len(*vulnerableFunctions) != 0 {
		t.Errorf("Expected no vulnerable functions, got %v", vulnerableFunctions)
	}
}
