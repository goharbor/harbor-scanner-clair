package persistence

import (
	"github.com/goharbor/harbor-scanner-clair/pkg/job"
	"github.com/goharbor/harbor-scanner-clair/pkg/model/harbor"
)

// Store defines methods for persisting ScanJobs and associated ScanReports.
type Store interface {
	Save(scanJob job.ScanJob) error
	Get(scanJobID string) (*job.ScanJob, error)
	UpdateStatus(scanJobID string, newStatus job.Status, error ...string) error
	UpdateReport(scanJobID string, reports harbor.ScanReport) error
}
