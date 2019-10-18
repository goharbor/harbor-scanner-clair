package mock

import (
	"github.com/goharbor/harbor-scanner-clair/pkg/model/harbor"
	"github.com/stretchr/testify/mock"
)

type Scanner struct {
	mock.Mock
}

func NewScanner() *Scanner {
	return &Scanner{}
}

func (s *Scanner) Scan(req harbor.ScanRequest) (harbor.ScanResponse, error) {
	args := s.Called(req)
	return args.Get(0).(harbor.ScanResponse), args.Error(1)
}

func (s *Scanner) GetReport(scanRequestID string) (harbor.ScanReport, error) {
	args := s.Called(scanRequestID)
	return args.Get(0).(harbor.ScanReport), args.Error(1)
}
