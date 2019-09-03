package harbor

// Sevxxx is the list of severity of image after scanning.
const (
	_ Severity = iota
	SevNone
	SevUnknown
	SevLow
	SevMedium
	SevHigh
)

type ScanRequest struct {
	ID                    string `json:"id"`
	RegistryURL           string `json:"registry_url"`
	RegistryAuthorization string `json:"registry_authorization"`
	ArtifactRepository    string `json:"artifact_repository"`
	ArtifactDigest        string `json:"artifact_digest"`
}

type VulnerabilityReport struct {
	Severity        Severity             `json:"severity"`
	Vulnerabilities []*VulnerabilityItem `json:"vulnerabilities"`
}

// Severity represents the severity of a image/component in terms of vulnerability.
type Severity int64

// VulnerabilityItem is an item in the vulnerability result returned by vulnerability details API.
type VulnerabilityItem struct {
	ID          string   `json:"id"`
	Severity    Severity `json:"severity"`
	Pkg         string   `json:"package"`
	Version     string   `json:"version"`
	Description string   `json:"description"`
	Link        string   `json:"link"`
	Fixed       string   `json:"fixedVersion,omitempty"`
}

type ScannerMetadata struct {
	Name         string        `json:"name"`
	Vendor       string        `json:"vendor"`
	Version      string        `json:"version"`
	Capabilities []*Capability `json:"capabilities"`
}

type Capability struct {
	ArtifactMIMETypes []string `json:"artifact_mime_types"`
	ReportMIMETypes   []string `json:"report_mime_types"`
}

type Error struct {
	Message string `json:"message"`
}
