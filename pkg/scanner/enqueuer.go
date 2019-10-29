package scanner

import (
	"github.com/goharbor/harbor-scanner-clair/pkg/job"
	"github.com/goharbor/harbor-scanner-clair/pkg/model/harbor"
	"github.com/goharbor/harbor-scanner-clair/pkg/persistence"
	"github.com/goharbor/harbor-scanner-clair/pkg/scanner/clair"
	"github.com/goharbor/harbor-scanner-clair/pkg/work"
	"github.com/google/uuid"
	"golang.org/x/xerrors"
)

// Enqueuer wraps the Enqueue method.
// Enqueue enqueues the specify ScanRequest for async processing and returns the async job's identifier.
type Enqueuer interface {
	Enqueue(request harbor.ScanRequest) (string, error)
}

// NewEnqueuer constructs the default Enqueuer.
func NewEnqueuer(pool *work.Pool, scanner clair.Scanner, store persistence.Store) Enqueuer {
	return &enqueuer{
		pool:    pool,
		scanner: scanner,
		store:   store,
	}
}

type enqueuer struct {
	store   persistence.Store
	pool    *work.Pool
	scanner clair.Scanner
}

func (e *enqueuer) Enqueue(request harbor.ScanRequest) (string, error) {
	jobID := uuid.New().String()
	err := e.store.Save(job.ScanJob{
		ID:     jobID,
		Status: job.Queued},
	)
	if err != nil {
		return "", xerrors.Errorf("saving scan job: %w", err)
	}
	e.pool.Run(NewWorker(e.store, e.scanner, jobID, request))
	return jobID, nil
}
