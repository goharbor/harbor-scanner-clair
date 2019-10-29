package mock

import (
	"github.com/goharbor/harbor-scanner-clair/pkg/model/harbor"
	"github.com/stretchr/testify/mock"
)

type Enqueuer struct {
	mock.Mock
}

func NewEnqueuer() *Enqueuer {
	return &Enqueuer{}
}

func (e *Enqueuer) Enqueue(request harbor.ScanRequest) (string, error) {
	args := e.Called(request)
	return args.String(0), args.Error(1)
}
