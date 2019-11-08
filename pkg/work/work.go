package work

import (
	log "github.com/sirupsen/logrus"
)

// Worker must be implemented by types that want to use the worker pool.
type Worker interface {
	Task()
}

// Pool provides a pool of goroutines that can execute any Worker tasks
// that are submitted
type Pool struct {
	tasks chan Worker
	stop  chan struct{}
}

func New() *Pool {
	return &Pool{
		tasks: make(chan Worker),
		stop:  make(chan struct{}),
	}
}

func (p *Pool) Start() {
	go func() {
		log.Trace("Work pool started")
		for {
			select {
			case w := <-p.tasks:
				go func() {
					log.Trace("Work pool received new task")
					w.Task()
				}()
			case <-p.stop:
				log.Trace("Work pool shutdown completed")
				return
			}
		}
	}()
}

// Run submits work to the pool
func (p *Pool) Run(w Worker) {
	p.tasks <- w
}

// Shutdown waits for all the goroutines to shutdown.
func (p *Pool) Shutdown() {
	log.Trace("Work pool shutdown started")
	close(p.stop)
}
