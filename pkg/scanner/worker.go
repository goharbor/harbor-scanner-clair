package scanner

import (
	"github.com/goharbor/harbor-scanner-clair/pkg/job"
	"github.com/goharbor/harbor-scanner-clair/pkg/model/harbor"
	"github.com/goharbor/harbor-scanner-clair/pkg/persistence"
	"github.com/goharbor/harbor-scanner-clair/pkg/scanner/clair"
	"github.com/goharbor/harbor-scanner-clair/pkg/work"
	log "github.com/sirupsen/logrus"
)

type worker struct {
	store   persistence.Store
	scanner clair.Scanner
	jobID   string
	request harbor.ScanRequest
}

func NewWorker(store persistence.Store, scanner clair.Scanner, jobID string, request harbor.ScanRequest) work.Worker {
	return &worker{
		store:   store,
		scanner: scanner,
		jobID:   jobID,
		request: request,
	}
}

func (as *worker) Task() {
	log.Debugf("Scan worker started processing: %v", as.request.Artifact)

	err := as.scan()

	if err != nil {
		log.WithError(err).Error("Scan worker failed")
		err = as.store.UpdateStatus(as.jobID, job.Failed, err.Error())
		if err != nil {
			log.WithError(err).Errorf("Error while updating scan job status to %s", job.Failed.String())
		}
	}
}

func (as *worker) scan() error {
	err := as.store.UpdateStatus(as.jobID, job.Pending)
	if err != nil {
		return err
	}
	report, err := as.scanner.Scan(as.request)
	if err != nil {
		return err
	}
	err = as.store.UpdateReport(as.jobID, report)
	if err != nil {
		return err
	}
	err = as.store.UpdateStatus(as.jobID, job.Finished)
	if err != nil {
		return err
	}
	return nil
}
