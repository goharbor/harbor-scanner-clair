package work

import (
	"github.com/goharbor/harbor-scanner-clair/pkg/etc"
	"sync"
)

// Worker must be implemented by types that want to use the worker pool.
type Worker interface {
	Task()
}

// Pool provides a pool of goroutines that can execute any Worker tasks
// that are submitted
type Pool struct {
	tasks chan Worker
	wg    sync.WaitGroup
}

func New(config etc.WorkPoolConfig) *Pool {
	p := Pool{
		tasks: make(chan Worker),
	}
	p.wg.Add(config.MaxGoroutines)
	for i := 0; i < config.MaxGoroutines; i++ {
		go func() {
			for w := range p.tasks {
				w.Task()
			}
			p.wg.Done()
		}()
	}
	return &p
}

// Run submits work to the pool
func (p *Pool) Run(w Worker) {
	p.tasks <- w
}

// Shutdown waits for all the goroutines to shutdown.
func (p *Pool) Shutdown() {
	close(p.tasks)
}
