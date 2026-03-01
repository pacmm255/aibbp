package preprocessor

import (
	"encoding/json"
	"fmt"

	"github.com/rs/zerolog/log"

	"github.com/aibbp/aibbp/internal/config"
	"github.com/aibbp/aibbp/internal/models"
)

// Pipeline orchestrates all preprocessing stages.
type Pipeline struct {
	stages []Stage
	cfg    config.PreprocessorConfig
}

// NewPipeline creates a pipeline with the standard 4-stage configuration.
func NewPipeline(cfg config.PreprocessorConfig) *Pipeline {
	return &Pipeline{
		stages: []Stage{
			NewFilter(cfg.Filter),
			NewConverter(),
			NewDedup(cfg.SimhashThreshold),
			NewCapper(cfg.MaxOutputBytes, cfg.ArrayTruncation.MaxItems),
		},
		cfg: cfg,
	}
}

// Process runs all stages sequentially, returning the reduced results.
func (p *Pipeline) Process(output *models.ScanOutput) ([]byte, error) {
	results := output.Results
	initialCount := len(results)

	for _, stage := range p.stages {
		var err error
		beforeCount := len(results)
		results, err = stage.Process(results)
		if err != nil {
			return nil, fmt.Errorf("stage %s: %w", stage.Name(), err)
		}

		log.Debug().
			Str("stage", stage.Name()).
			Int("before", beforeCount).
			Int("after", len(results)).
			Float64("reduction_pct", reductionPct(beforeCount, len(results))).
			Msg("preprocessor stage complete")
	}

	data, err := json.Marshal(results)
	if err != nil {
		return nil, fmt.Errorf("marshal results: %w", err)
	}

	// Final size cap
	if len(data) > p.cfg.MaxOutputBytes {
		data = data[:p.cfg.MaxOutputBytes]
	}

	log.Info().
		Int("initial_results", initialCount).
		Int("final_results", len(results)).
		Int("output_bytes", len(data)).
		Float64("total_reduction_pct", reductionPct(initialCount, len(results))).
		Msg("preprocessing complete")

	return data, nil
}

func reductionPct(before, after int) float64 {
	if before == 0 {
		return 0
	}
	return float64(before-after) / float64(before) * 100
}
