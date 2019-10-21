package clair

const (
	SeverityUnknown    = "unknown"
	SeverityNegligible = "negligible"
	SeverityLow        = "low"
	SeverityMedium     = "medium"
	SeverityHigh       = "high"
	SeverityCritical   = "critical"
)

// Layer is one of the tarballs used in the composition of an image, often expressed as a filesystem delta from
// another layer.
type Layer struct {
	Name           string            `json:"Name,omitempty"`
	NamespaceNames []string          `json:"NamespaceNames,omitempty"`
	Path           string            `json:"Path,omitempty"`
	Headers        map[string]string `json:"Headers,omitempty"`
	ParentName     string            `json:"ParentName,omitempty"`
	Format         string            `json:"Format,omitempty"`
	Features       []Feature         `json:"Features,omitempty"`
}

// Feature anything that when present in a filesystem could be an indication of a vulnerability (e.g. the presence
// of a file or an installed software package).
type Feature struct {
	Name            string          `json:"Name,omitempty"`
	NamespaceName   string          `json:"NamespaceName,omitempty"`
	VersionFormat   string          `json:"VersionFormat,omitempty"`
	Version         string          `json:"Version,omitempty"`
	Vulnerabilities []Vulnerability `json:"Vulnerabilities,omitempty"`
	AddedBy         string          `json:"AddedBy,omitempty"`
}

// Vulnerability ...
type Vulnerability struct {
	Name          string                 `json:"Name,omitempty"`
	NamespaceName string                 `json:"NamespaceName,omitempty"`
	Description   string                 `json:"Description,omitempty"`
	Link          string                 `json:"Link,omitempty"`
	Severity      string                 `json:"Severity,omitempty"`
	Metadata      map[string]interface{} `json:"Metadata,omitempty"`
	FixedBy       string                 `json:"FixedBy,omitempty"`
	FixedIn       []Feature              `json:"FixedIn,omitempty"`
}

// Error ...
type Error struct {
	Message string `json:"Message,omitempty"`
}

// LayerEnvelope ...
type LayerEnvelope struct {
	Layer *Layer `json:"Layer,omitempty"`
	Error *Error `json:"Error,omitempty"`
}
