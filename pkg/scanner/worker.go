package scanner

import (
	"github.com/goharbor/harbor-scanner-clair/pkg/harbor"
	"github.com/goharbor/harbor-scanner-clair/pkg/job"
	"github.com/goharbor/harbor-scanner-clair/pkg/persistence"
	log "github.com/sirupsen/logrus"
)

type worker struct {
	store   persistence.Store
	adapter Adapter
	jobID   string
	request harbor.ScanRequest
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
	err := as.store.UpdateStatus(as.jobID, job.Running)
	if err != nil {
		return err
	}
	report, err := as.adapter.Scan(as.request)
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
