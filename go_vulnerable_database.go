package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	_ "github.com/mattn/go-sqlite3"
)

type GoVuln struct {
	ID       string   `json:"id"`
	Modified string   `json:"modified"`
	Aliases  []string `json:"aliases"`
}

type GoVulnerableDatabase struct {
	db *sql.DB
}

type VulnerableFunction struct {
	Function string
	Library  string
	CVE      string
	GoID     string
}

func checkErr(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func dbErrorHandle(db *sql.DB) {
	err := db.Close()
	checkErr(err)
}

const DBFile string = "govulndb/go_vuln.db"

func UpdateHash(db *sql.DB, hash string) {
	_, err := db.Exec("INSERT INTO checksum (hash) VALUES (?)", hash)
	checkErr(err)
}

func tableExists(db *sql.DB, tableName string) bool {
	query := `SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?`
	var count int
	err := db.QueryRow(query, tableName).Scan(&count)
	checkErr(err)
	if err != nil {
		return false
	}
	return count > 0
}

func CreateDB(db *sql.DB) {
	//CREATE TABLE cve (
	//	id INTEGER PRIMARY KEY AUTOINCREMENT,
	//	go_id TEXT NOT NULL,
	//	cve_id TEXT NOT NULL
	//);
	// Drop this table if exist
	_, err := db.Exec("DROP TABLE IF EXISTS cve")
	checkErr(err)

	_, err = db.Exec("CREATE TABLE cve (id INTEGER PRIMARY KEY AUTOINCREMENT, go_id TEXT NOT NULL, cve_id TEXT NOT NULL)")
	checkErr(err)

	// CREATE TABLE checksum (
	// id INTEGER PRIMARY KEY AUTOINCREMENT
	// hash TEXT NOT NULL
	//);
	// Drop this table if exist
	_, err = db.Exec("DROP TABLE IF EXISTS checksum")
	checkErr(err)

	_, err = db.Exec("CREATE TABLE checksum (id INTEGER PRIMARY KEY AUTOINCREMENT, hash TEXT NOT NULL)")
	checkErr(err)

}

func InjectAllData(db *sql.DB, all_files []GoVuln) {
	tx, err := db.Begin()
	checkErr(err)
	stmt, err := tx.Prepare("INSERT INTO cve (go_id, cve_id) VALUES (?, ?)")
	checkErr(err)
	// Insert the data into the cve table
	for _, file := range all_files {
		go_id := file.ID
		aliases := file.Aliases
		for _, alias := range aliases {
			_, err = stmt.Exec(go_id, alias)
			if err != nil {
				fmt.Println(err)
				err = tx.Rollback()
				checkErr(err)
				return
			}

		}
		checkErr(err)
	}
	err = tx.Commit()
	checkErr(err)
}

func GetNewData() (string, []GoVuln) {
	url := "https://vuln.go.dev/index/vulns.json"
	// Download the zip file

	resp, err := http.Get(url)
	checkErr(err)

	body, err := io.ReadAll(resp.Body)
	checkErr(err)

	hash := sha256.New()
	_, err = hash.Write(body)
	checkErr(err)

	sum := hash.Sum(nil)

	var result []GoVuln
	err = json.Unmarshal(body, &result)
	checkErr(err)
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Fatal(err)
		}
	}(resp.Body)
	return fmt.Sprintf("%x", sum), result
}

func InitDB() *sql.DB {

	_, err := os.Stat(filepath.Dir(DBFile))
	if os.IsNotExist(err) {
		err := os.MkdirAll(filepath.Dir(DBFile), 0755)
		checkErr(err)
	}

	// Check whether the file exists
	db, err := sql.Open("sqlite3", DBFile)
	checkErr(err)

	if !(tableExists(db, "cve") && tableExists(db, "checksum")) {
		CreateDB(db)
	}

	// query hash from checksum table
	rows, err := db.Query("SELECT hash FROM checksum ORDER BY id DESC LIMIT 1")
	checkErr(err)
	existHash := ""
	for rows.Next() {
		err = rows.Scan(&existHash)
		checkErr(err)
	}

	newHash, raw := GetNewData()
	if existHash != newHash {
		// Update the cve table
		_, err = db.Exec("DELETE FROM cve")
		checkErr(err)
		// Insert the data into the cve table
		InjectAllData(db, raw)
		// Update the checksum table
		UpdateHash(db, newHash)
	}

	return db
}

func NewGoVulnDatabase() *GoVulnerableDatabase {
	db := InitDB()
	return &GoVulnerableDatabase{db: db}
}

func (gdb *GoVulnerableDatabase) GetGOIDsByCVE(cve string) (bool, []string) {
	// Check whether the cve is in the database
	//cve input is "cve-2015-0001"
	// make it upper case
	cve = strings.ToUpper(cve)
	rows, err := gdb.db.Query("SELECT go_id FROM cve WHERE cve_id=?", cve)
	checkErr(err)
	var result []string
	var go_id string
	for rows.Next() {
		err = rows.Scan(&go_id)
		checkErr(err)
		result = append(result, go_id)
	}
	return len(result) > 0, result
}

func (gdb *GoVulnerableDatabase) GetVulnerableFunctionsByGOID(GoID string, cve string) *[]VulnerableFunction {

	var result []VulnerableFunction

	url := fmt.Sprintf("https://vuln.go.dev/ID/%s.json", GoID)
	resp, err := http.Get(url)
	checkErr(err)
	body, err := io.ReadAll(resp.Body)
	checkErr(err)
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		checkErr(err)
	}(resp.Body)
	var goIdDetail VulnReport
	err = json.Unmarshal(body, &goIdDetail)
	checkErr(err)
	// check is affected field exist
	affected := goIdDetail.Affected
	if affected == nil {
		return &result
	}

	for _, affectedMap := range affected {
		// check the affectedMap[ecosystem_specific][imports] exist
		ecosystemSpecific := affectedMap.EcosystemSpecific
		imports := ecosystemSpecific.Imports
		if imports == nil {
			continue
		}

		for _, importsMap := range imports {
			packagePath := importsMap.Path
			symbols := importsMap.Symbols
			for _, symbol := range symbols {
				vulnerableFunctionItem := VulnerableFunction{
					GoID:     GoID,
					Library:  packagePath,
					Function: symbol,
					CVE:      cve,
				}
				result = append(result, vulnerableFunctionItem)
			}

		}
	}
	return &result
}

func (gdb *GoVulnerableDatabase) GetVulnerableFunctionsByCVE(cve string) *[]VulnerableFunction {
	_, goIDs := gdb.GetGOIDsByCVE(cve)
	var result []VulnerableFunction
	for _, goID := range goIDs {
		vulnerableFunctions := gdb.GetVulnerableFunctionsByGOID(goID, cve)
		result = append(result, *vulnerableFunctions...)
	}
	return &result
}

func (gdb *GoVulnerableDatabase) Close() {
	dbErrorHandle(gdb.db)
}
