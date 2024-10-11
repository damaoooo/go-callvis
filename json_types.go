package main

import "time"

type VulnReport struct {
	SchemaVersion    string       `json:"schema_version"`
	ID               string       `json:"id"`
	Modified         time.Time    `json:"modified"`
	Published        time.Time    `json:"published"`
	Aliases          []string     `json:"aliases"`
	Summary          string       `json:"summary"`
	Details          string       `json:"details"`
	Affected         []Affected   `json:"affected"`
	References       []Reference  `json:"references"`
	Credits          []Credit     `json:"credits"`
	DatabaseSpecific DatabaseSpec `json:"database_specific"`
}

type Affected struct {
	Package           Package       `json:"package"`
	Ranges            []Range       `json:"ranges"`
	EcosystemSpecific EcosystemSpec `json:"ecosystem_specific"`
}

type Package struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type Range struct {
	Type   string  `json:"type"`
	Events []Event `json:"events"`
}

type Event struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
}

type EcosystemSpec struct {
	Imports []Import `json:"imports"`
}

type Import struct {
	Path    string   `json:"path"`
	Symbols []string `json:"symbols"`
}

type Reference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type Credit struct {
	Name string `json:"name"`
}

type DatabaseSpec struct {
	URL          string `json:"url"`
	ReviewStatus string `json:"review_status"`
}

type TrivySBOMReport struct {
	SchemaVersion int       `json:"SchemaVersion"`
	CreatedAt     time.Time `json:"CreatedAt"`
	ArtifactName  string    `json:"ArtifactName"`
	ArtifactType  string    `json:"ArtifactType"`
	Metadata      Metadata  `json:"Metadata"`
	Results       []Result  `json:"Results"`
}

type Metadata struct {
	ImageConfig ImageConfig `json:"ImageConfig"`
}

type ImageConfig struct {
	Architecture string    `json:"architecture"`
	Created      time.Time `json:"created"`
	OS           string    `json:"os"`
	RootFS       RootFS    `json:"rootfs"`
	Config       Config    `json:"config"`
}

type RootFS struct {
	Type    string        `json:"type"`
	DiffIDs []interface{} `json:"diff_ids"` // Adjust type if diff_ids are not always null
}

type Config struct {
	// Add fields as needed based on your actual JSON content
}

type Result struct {
	Target          string          `json:"Target"`
	Class           string          `json:"Class"`
	Type            string          `json:"Type"`
	Vulnerabilities []Vulnerability `json:"Vulnerabilities"`
}

type Vulnerability struct {
	VulnerabilityID  string         `json:"VulnerabilityID"`
	PkgID            string         `json:"PkgID"`
	PkgName          string         `json:"PkgName"`
	PkgIdentifier    PkgIdentifier  `json:"PkgIdentifier"`
	InstalledVersion string         `json:"InstalledVersion"`
	FixedVersion     string         `json:"FixedVersion"`
	Status           string         `json:"Status"`
	Layer            Layer          `json:"Layer"`
	SeveritySource   string         `json:"SeveritySource"`
	PrimaryURL       string         `json:"PrimaryURL"`
	DataSource       DataSource     `json:"DataSource"`
	Title            string         `json:"Title"`
	Description      string         `json:"Description"`
	Severity         string         `json:"Severity"`
	VendorSeverity   VendorSeverity `json:"VendorSeverity"`
	CVSS             CVSS           `json:"CVSS"`
	References       []string       `json:"References"`
	PublishedDate    time.Time      `json:"PublishedDate"`
	LastModifiedDate time.Time      `json:"LastModifiedDate"`
	CweIDs           []string       `json:"CweIDs,omitempty"` // Optional field in case it doesn't exist
}

type PkgIdentifier struct {
	PURL string `json:"PURL"`
	UID  string `json:"UID"`
}

type Layer struct {
	// Add fields as needed based on your actual JSON content
}

type DataSource struct {
	ID   string `json:"ID"`
	Name string `json:"Name"`
	URL  string `json:"URL"`
}

type VendorSeverity struct {
	Ghsa   int `json:"ghsa"`
	Nvd    int `json:"nvd,omitempty"`
	Redhat int `json:"redhat,omitempty"`
}

type CVSS struct {
	Ghsa   CVSSScore `json:"ghsa"`
	Nvd    CVSSScore `json:"nvd,omitempty"`
	Redhat CVSSScore `json:"redhat,omitempty"`
}

type CVSSScore struct {
	V3Vector string  `json:"V3Vector"`
	V3Score  float64 `json:"V3Score"`
}
