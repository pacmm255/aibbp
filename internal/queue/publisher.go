package queue

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/nats-io/nats.go/jetstream"
	"github.com/rs/zerolog/log"
)

// Publisher publishes messages to NATS JetStream with deduplication.
type Publisher struct {
	client *Client
}

// NewPublisher creates a new Publisher.
func NewPublisher(client *Client) *Publisher {
	return &Publisher{client: client}
}

// Publish publishes a message with optional dedup via MsgID.
func (p *Publisher) Publish(ctx context.Context, subject string, data any, msgID string) error {
	payload, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("marshal message: %w", err)
	}

	opts := []jetstream.PublishOpt{}
	if msgID != "" {
		opts = append(opts, jetstream.WithMsgID(msgID))
	}

	ack, err := p.client.js.Publish(ctx, subject, payload, opts...)
	if err != nil {
		return fmt.Errorf("publish to %s: %w", subject, err)
	}

	if ack.Duplicate {
		log.Debug().
			Str("subject", subject).
			Str("msg_id", msgID).
			Msg("duplicate message detected, skipped")
		return nil
	}

	log.Debug().
		Str("subject", subject).
		Str("msg_id", msgID).
		Uint64("seq", ack.Sequence).
		Msg("published message")

	return nil
}

// PublishRaw publishes raw bytes.
func (p *Publisher) PublishRaw(ctx context.Context, subject string, data []byte, msgID string) error {
	opts := []jetstream.PublishOpt{}
	if msgID != "" {
		opts = append(opts, jetstream.WithMsgID(msgID))
	}

	_, err := p.client.js.Publish(ctx, subject, data, opts...)
	if err != nil {
		return fmt.Errorf("publish raw to %s: %w", subject, err)
	}
	return nil
}
