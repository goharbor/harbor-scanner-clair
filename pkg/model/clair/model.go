package clair

const (
	SeverityNone     = "negligible"
	SeverityLow      = "low"
	SeverityMedium   = "medium"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)

// ClairLayer ...
type ClairLayer struct {
	Name           string            `json:"Name,omitempty"`
	NamespaceNames []string          `json:"NamespaceNames,omitempty"`
	Path           string            `json:"Path,omitempty"`
	Headers        map[string]string `json:"Headers,omitempty"`
	ParentName     string            `json:"ParentName,omitempty"`
	Format         string            `json:"Format,omitempty"`
	Features       []ClairFeature    `json:"Features,omitempty"`
}

// ClairFeature ...
type ClairFeature struct {
	Name            string               `json:"Name,omitempty"`
	NamespaceName   string               `json:"NamespaceName,omitempty"`
	VersionFormat   string               `json:"VersionFormat,omitempty"`
	Version         string               `json:"Version,omitempty"`
	Vulnerabilities []ClairVulnerability `json:"Vulnerabilities,omitempty"`
	AddedBy         string               `json:"AddedBy,omitempty"`
}

// ClairVulnerability ...
type ClairVulnerability struct {
	Name          string                 `json:"Name,omitempty"`
	NamespaceName string                 `json:"NamespaceName,omitempty"`
	Description   string                 `json:"Description,omitempty"`
	Link          string                 `json:"Link,omitempty"`
	Severity      string                 `json:"Severity,omitempty"`
	Metadata      map[string]interface{} `json:"Metadata,omitempty"`
	FixedBy       string                 `json:"FixedBy,omitempty"`
	FixedIn       []ClairFeature         `json:"FixedIn,omitempty"`
}

// ClairError ...
type ClairError struct {
	Message string `json:"Message,omitempty"`
}

// ClairLayerEnvelope ...
type ClairLayerEnvelope struct {
	Layer *ClairLayer `json:"Layer,omitempty"`
	Error *ClairError `json:"Error,omitempty"`
}
