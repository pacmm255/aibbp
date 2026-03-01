package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/aibbp/aibbp/internal/config"
	"github.com/aibbp/aibbp/internal/models"
	"github.com/aibbp/aibbp/internal/queue"
	"github.com/aibbp/aibbp/internal/scanner"
	"github.com/aibbp/aibbp/internal/worker"

	// Register all scanner implementations
	_ "github.com/aibbp/aibbp/internal/scanner/dnsx"
	_ "github.com/aibbp/aibbp/internal/scanner/ffuf"
	_ "github.com/aibbp/aibbp/internal/scanner/gowitness"
	_ "github.com/aibbp/aibbp/internal/scanner/httpx"
	_ "github.com/aibbp/aibbp/internal/scanner/katana"
	_ "github.com/aibbp/aibbp/internal/scanner/masscan"
	_ "github.com/aibbp/aibbp/internal/scanner/nmap"
	_ "github.com/aibbp/aibbp/internal/scanner/nuclei"
	_ "github.com/aibbp/aibbp/internal/scanner/subfinder"
)

func main() {
	// Setup logging
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	cfg, err := config.Load("")
	if err != nil {
		log.Fatal().Err(err).Msg("failed to load config")
	}

	ctx := context.Background()

	// Connect to NATS
	natsClient, err := queue.NewClient(ctx, cfg.NATS)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to connect to NATS")
	}
	defer natsClient.Close()

	publisher := queue.NewPublisher(natsClient)

	// Create all available scanners
	scanners := scanner.CreateAll(cfg.Scanning)
	log.Info().Int("available", len(scanners)).Msg("scanners loaded")
	for st := range scanners {
		log.Info().Str("scanner", string(st)).Msg("scanner available")
	}

	// Create consumer for scan tasks
	consumer := queue.NewConsumer(natsClient, queue.ConsumerConfig{
		Stream:       queue.StreamTasks,
		ConsumerName: queue.ConsumerScanWorker,
		FilterSubj:   queue.SubjectTaskScan,
		BatchSize:    1,
	})

	// Create worker runner
	runner := worker.New("scanner-worker")
	runner.Add(func(ctx context.Context) error {
		return consumer.Start(ctx, func(ctx context.Context, msg jetstream.Msg) error {
			return handleScanTask(ctx, msg, scanners, publisher, cfg.Scanning)
		})
	})

	if err := runner.Run(); err != nil {
		log.Fatal().Err(err).Msg("scanner worker failed")
	}
}

func handleScanTask(ctx context.Context, msg jetstream.Msg, scanners map[models.ScannerType]scanner.Scanner, pub *queue.Publisher, cfg config.ScanConfig) error {
	var task models.TaskMessage
	if err := json.Unmarshal(msg.Data(), &task); err != nil {
		log.Error().Err(err).Msg("unmarshal task message")
		return err
	}

	log.Info().
		Str("task_id", task.ID.String()).
		Str("scanner", string(task.Scanner)).
		Str("target", task.Target).
		Msg("processing scan task")

	s, ok := scanners[task.Scanner]
	if !ok {
		return fmt.Errorf("scanner not available: %s", task.Scanner)
	}

	input := models.ScanInput{
		ID:     task.ID,
		Target: task.Target,
		Type:   task.Scanner,
	}

	output, err := s.Run(ctx, input)
	if err != nil {
		log.Error().Err(err).Str("scanner", string(task.Scanner)).Msg("scan failed")
		// Still publish the error result
	}

	if output != nil {
		// Publish raw results for preprocessing
		if pubErr := pub.Publish(ctx, queue.SubjectScanResultRaw, output, task.ID.String()); pubErr != nil {
			return fmt.Errorf("publish scan result: %w", pubErr)
		}

		log.Info().
			Str("task_id", task.ID.String()).
			Int("results", len(output.Results)).
			Str("duration", output.Duration.String()).
			Msg("scan completed")
	}

	return nil
}
