package queue

import (
	"context"
	"fmt"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/rs/zerolog/log"

	"github.com/aibbp/aibbp/internal/config"
)

// Client wraps a NATS connection with JetStream.
type Client struct {
	conn *nats.Conn
	js   jetstream.JetStream
	cfg  config.NATSConfig
}

// NewClient creates a NATS JetStream client.
func NewClient(ctx context.Context, cfg config.NATSConfig) (*Client, error) {
	opts := []nats.Option{
		nats.MaxReconnects(cfg.MaxReconnect),
		nats.ReconnectWait(cfg.ReconnectWait()),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			if err != nil {
				log.Warn().Err(err).Msg("NATS disconnected")
			}
		}),
		nats.ReconnectHandler(func(_ *nats.Conn) {
			log.Info().Msg("NATS reconnected")
		}),
		nats.ErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) {
			log.Error().Err(err).Msg("NATS async error")
		}),
	}

	conn, err := nats.Connect(cfg.URL, opts...)
	if err != nil {
		return nil, fmt.Errorf("nats connect: %w", err)
	}

	js, err := jetstream.New(conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("jetstream new: %w", err)
	}

	client := &Client{
		conn: conn,
		js:   js,
		cfg:  cfg,
	}

	if err := client.ensureStreams(ctx); err != nil {
		conn.Close()
		return nil, fmt.Errorf("ensure streams: %w", err)
	}

	log.Info().Str("url", cfg.URL).Msg("connected to NATS JetStream")

	return client, nil
}

// ensureStreams creates all required JetStream streams if they don't exist.
func (c *Client) ensureStreams(ctx context.Context) error {
	streams := []jetstream.StreamConfig{
		{
			Name:      StreamTasks,
			Subjects:  []string{"tasks.>"},
			Retention: jetstream.WorkQueuePolicy,
			MaxMsgs:   50000,
			Storage:   jetstream.FileStorage,
			Replicas:  1,
		},
		{
			Name:      StreamScans,
			Subjects:  []string{"scan.>"},
			Retention: jetstream.WorkQueuePolicy,
			MaxMsgs:   10000,
			Storage:   jetstream.FileStorage,
			Replicas:  1,
		},
		{
			Name:      StreamResults,
			Subjects:  []string{"results.>"},
			Retention: jetstream.LimitsPolicy,
			MaxAge:    7 * 24 * time.Hour,
			Storage:   jetstream.FileStorage,
			Replicas:  1,
		},
		{
			Name:      StreamEvents,
			Subjects:  []string{"events.>"},
			Retention: jetstream.LimitsPolicy,
			MaxAge:    30 * 24 * time.Hour,
			Storage:   jetstream.FileStorage,
			Replicas:  1,
		},
	}

	for _, cfg := range streams {
		_, err := c.js.CreateOrUpdateStream(ctx, cfg)
		if err != nil {
			return fmt.Errorf("create stream %s: %w", cfg.Name, err)
		}
		log.Debug().Str("stream", cfg.Name).Msg("stream ready")
	}

	return nil
}

// JS returns the JetStream context for direct access.
func (c *Client) JS() jetstream.JetStream {
	return c.js
}

// Conn returns the underlying NATS connection.
func (c *Client) Conn() *nats.Conn {
	return c.conn
}

// Close closes the NATS connection.
func (c *Client) Close() {
	if c.conn != nil {
		c.conn.Close()
	}
}

// Healthy returns true if the NATS connection is active.
func (c *Client) Healthy() bool {
	return c.conn != nil && c.conn.IsConnected()
}
