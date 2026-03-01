package main

import (
	"context"
	"encoding/json"
	"os"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/aibbp/aibbp/internal/config"
	"github.com/aibbp/aibbp/internal/models"
	"github.com/aibbp/aibbp/internal/preprocessor"
	"github.com/aibbp/aibbp/internal/queue"
	"github.com/aibbp/aibbp/internal/worker"
)

func main() {
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	cfg, err := config.Load("")
	if err != nil {
		log.Fatal().Err(err).Msg("failed to load config")
	}

	ctx := context.Background()

	natsClient, err := queue.NewClient(ctx, cfg.NATS)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to connect to NATS")
	}
	defer natsClient.Close()

	publisher := queue.NewPublisher(natsClient)
	pipeline := preprocessor.NewPipeline(cfg.Preprocessor)

	consumer := queue.NewConsumer(natsClient, queue.ConsumerConfig{
		Stream:       queue.StreamScans,
		ConsumerName: queue.ConsumerPreprocessor,
		FilterSubj:   queue.SubjectScanResultRaw,
		BatchSize:    1,
	})

	runner := worker.New("preprocessor-worker")
	runner.Add(func(ctx context.Context) error {
		return consumer.Start(ctx, func(ctx context.Context, msg jetstream.Msg) error {
			return handlePreprocess(ctx, msg, pipeline, publisher)
		})
	})

	if err := runner.Run(); err != nil {
		log.Fatal().Err(err).Msg("preprocessor worker failed")
	}
}

func handlePreprocess(ctx context.Context, msg jetstream.Msg, pipeline *preprocessor.Pipeline, pub *queue.Publisher) error {
	var output models.ScanOutput
	if err := json.Unmarshal(msg.Data(), &output); err != nil {
		log.Error().Err(err).Msg("unmarshal scan output")
		return err
	}

	log.Info().
		Str("scan_id", output.ScanID.String()).
		Str("scanner", string(output.ScannerType)).
		Int("raw_results", len(output.Results)).
		Msg("preprocessing scan results")

	processed, err := pipeline.Process(&output)
	if err != nil {
		log.Error().Err(err).Msg("preprocessing failed")
		return err
	}

	result := models.ScanResultMessage{
		ScanID:      output.ScanID,
		ScannerType: output.ScannerType,
		Target:      output.Target,
		Results:     processed,
		ByteSize:    len(processed),
	}

	if err := pub.Publish(ctx, queue.SubjectScanResultPreprocessed, result, output.ScanID.String()+"-pp"); err != nil {
		return err
	}

	log.Info().
		Str("scan_id", output.ScanID.String()).
		Int("output_bytes", len(processed)).
		Msg("preprocessing complete")

	return nil
}
