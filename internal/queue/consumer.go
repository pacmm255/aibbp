package queue

import (
	"context"
	"fmt"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/rs/zerolog/log"
)

// MessageHandler processes a single message. Return nil to ACK, error to NAK.
type MessageHandler func(ctx context.Context, msg jetstream.Msg) error

// Consumer provides durable pull consumer functionality.
type Consumer struct {
	client       *Client
	stream       string
	consumerName string
	filterSubj   string
	batchSize    int
	ackWait      time.Duration
	maxDeliver   int
}

// ConsumerConfig configures a consumer.
type ConsumerConfig struct {
	Stream       string
	ConsumerName string
	FilterSubj   string
	BatchSize    int
	AckWait      time.Duration
	MaxDeliver   int
}

// NewConsumer creates a durable pull consumer.
func NewConsumer(client *Client, cfg ConsumerConfig) *Consumer {
	if cfg.BatchSize == 0 {
		cfg.BatchSize = 1
	}
	if cfg.AckWait == 0 {
		cfg.AckWait = 30 * time.Second
	}
	if cfg.MaxDeliver == 0 {
		cfg.MaxDeliver = 5
	}

	return &Consumer{
		client:       client,
		stream:       cfg.Stream,
		consumerName: cfg.ConsumerName,
		filterSubj:   cfg.FilterSubj,
		batchSize:    cfg.BatchSize,
		ackWait:      cfg.AckWait,
		maxDeliver:   cfg.MaxDeliver,
	}
}

// Start begins consuming messages, blocking until context is cancelled.
func (c *Consumer) Start(ctx context.Context, handler MessageHandler) error {
	consumerCfg := jetstream.ConsumerConfig{
		Durable:       c.consumerName,
		AckPolicy:     jetstream.AckExplicitPolicy,
		AckWait:       c.ackWait,
		MaxDeliver:    c.maxDeliver,
		FilterSubject: c.filterSubj,
	}

	cons, err := c.client.js.CreateOrUpdateConsumer(ctx, c.stream, consumerCfg)
	if err != nil {
		return fmt.Errorf("create consumer %s: %w", c.consumerName, err)
	}

	log.Info().
		Str("consumer", c.consumerName).
		Str("stream", c.stream).
		Str("filter", c.filterSubj).
		Msg("consumer started")

	for {
		select {
		case <-ctx.Done():
			log.Info().Str("consumer", c.consumerName).Msg("consumer stopping")
			return ctx.Err()
		default:
		}

		msgs, err := cons.Fetch(c.batchSize, jetstream.FetchMaxWait(5*time.Second))
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			log.Warn().Err(err).Str("consumer", c.consumerName).Msg("fetch error, retrying")
			time.Sleep(time.Second)
			continue
		}

		for msg := range msgs.Messages() {
			if err := c.processMessage(ctx, handler, msg); err != nil {
				log.Error().Err(err).
					Str("consumer", c.consumerName).
					Str("subject", msg.Subject()).
					Msg("message processing failed")
			}
		}

		if msgs.Error() != nil && msgs.Error().Error() != "nats: timeout" {
			log.Warn().Err(msgs.Error()).Str("consumer", c.consumerName).Msg("batch error")
		}
	}
}

// processMessage handles a single message with error recovery.
func (c *Consumer) processMessage(ctx context.Context, handler MessageHandler, msg jetstream.Msg) error {
	if err := handler(ctx, msg); err != nil {
		// NAK with delay for retry
		if nakErr := msg.NakWithDelay(5 * time.Second); nakErr != nil {
			log.Error().Err(nakErr).Msg("failed to NAK message")
		}
		return err
	}

	if err := msg.Ack(); err != nil {
		return fmt.Errorf("ack message: %w", err)
	}

	return nil
}
