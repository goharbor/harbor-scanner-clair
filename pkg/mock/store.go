package mock

import (
	"github.com/goharbor/harbor-scanner-clair/pkg/job"
	"github.com/goharbor/harbor-scanner-clair/pkg/model/harbor"
	"github.com/stretchr/testify/mock"
)

type Store struct {
	mock.Mock
}

func NewStore() *Store {
	return &Store{}
}

func (s *Store) Save(scanJob job.ScanJob) error {
	args := s.Called(scanJob)
	return args.Error(0)
}

func (s *Store) Get(scanJobID string) (*job.ScanJob, error) {
	args := s.Called(scanJobID)
	return args.Get(0).(*job.ScanJob), args.Error(1)
}

func (s *Store) UpdateStatus(scanJobID string, newStatus job.Status, error ...string) error {
	args := s.Called(scanJobID, newStatus, error)
	return args.Error(0)
}

func (s *Store) UpdateReport(scanJobID string, reports harbor.ScanReport) error {
	args := s.Called(scanJobID, reports)
	return args.Error(0)
}
