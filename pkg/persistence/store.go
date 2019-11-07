package persistence

import (
	"github.com/goharbor/harbor-scanner-clair/pkg/harbor"
	"github.com/goharbor/harbor-scanner-clair/pkg/job"
)

// Store defines methods for persisting ScanJobs and associated ScanReports.
type Store interface {
	Create(scanJob job.ScanJob) error
	Get(scanJobID string) (*job.ScanJob, error)
	UpdateStatus(scanJobID string, newStatus job.Status, error ...string) error
	UpdateReport(scanJobID string, reports harbor.ScanReport) error
}
