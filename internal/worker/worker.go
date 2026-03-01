package worker

import (
	"context"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/rs/zerolog/log"
)

// Runner manages worker lifecycle with graceful shutdown.
type Runner struct {
	name    string
	workers []func(ctx context.Context) error
}

// New creates a new worker runner.
func New(name string) *Runner {
	return &Runner{name: name}
}

// Add registers a worker function to run.
func (r *Runner) Add(fn func(ctx context.Context) error) {
	r.workers = append(r.workers, fn)
}

// Run starts all workers and blocks until shutdown signal.
func (r *Runner) Run() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Listen for shutdown signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	var wg sync.WaitGroup
	errCh := make(chan error, len(r.workers))

	// Start all workers
	for _, w := range r.workers {
		wg.Add(1)
		go func(fn func(ctx context.Context) error) {
			defer wg.Done()
			if err := fn(ctx); err != nil && ctx.Err() == nil {
				errCh <- err
			}
		}(w)
	}

	log.Info().Str("worker", r.name).Int("goroutines", len(r.workers)).Msg("worker started")

	// Wait for shutdown signal or worker error
	select {
	case sig := <-sigCh:
		log.Info().Str("signal", sig.String()).Msg("shutdown signal received")
	case err := <-errCh:
		log.Error().Err(err).Msg("worker error, initiating shutdown")
	}

	// Cancel context to stop all workers
	cancel()

	// Wait for graceful shutdown
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		log.Info().Str("worker", r.name).Msg("shutdown complete")
	case sig := <-sigCh:
		log.Warn().Str("signal", sig.String()).Msg("forced shutdown")
	}

	return nil
}
