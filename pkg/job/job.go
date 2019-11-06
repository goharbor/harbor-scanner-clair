package job

import (
	"github.com/goharbor/harbor-scanner-clair/pkg/harbor"
)

type Status int

const (
	Queued Status = iota
	Pending
	Finished
	Failed
)

func (s Status) String() string {
	if s < 0 || s > 3 {
		return "Unknown"
	}
	return [...]string{"Queued", "Pending", "Finished", "Failed"}[s]
}

type ScanJob struct {
	ID     string            `json:"id"`
	Status Status            `json:"status"`
	Error  string            `json:"error"`
	Report harbor.ScanReport `json:"report"`
}