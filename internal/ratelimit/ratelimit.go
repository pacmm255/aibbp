package ratelimit

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog/log"
)

// TokenBucket implements a Redis-backed token bucket rate limiter.
type TokenBucket struct {
	rdb       *redis.Client
	keyPrefix string
	rate      float64 // tokens per second
	burst     int     // max bucket size
	mu        sync.Mutex
}

// New creates a new Redis-backed token bucket.
func New(rdb *redis.Client, keyPrefix string, rps float64, burst int) *TokenBucket {
	return &TokenBucket{
		rdb:       rdb,
		keyPrefix: keyPrefix,
		rate:      rps,
		burst:     burst,
	}
}

// Allow checks if a request for the given key is allowed.
// If allowed, it consumes a token and returns true.
func (tb *TokenBucket) Allow(ctx context.Context, key string) (bool, error) {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	fullKey := fmt.Sprintf("%s:%s", tb.keyPrefix, key)

	// Lua script for atomic token bucket
	script := redis.NewScript(`
		local key = KEYS[1]
		local rate = tonumber(ARGV[1])
		local burst = tonumber(ARGV[2])
		local now = tonumber(ARGV[3])

		local data = redis.call('hmget', key, 'tokens', 'last_time')
		local tokens = tonumber(data[1])
		local last_time = tonumber(data[2])

		if tokens == nil then
			tokens = burst
			last_time = now
		end

		local elapsed = now - last_time
		tokens = math.min(burst, tokens + elapsed * rate)

		if tokens >= 1 then
			tokens = tokens - 1
			redis.call('hmset', key, 'tokens', tokens, 'last_time', now)
			redis.call('expire', key, 60)
			return 1
		end

		redis.call('hmset', key, 'tokens', tokens, 'last_time', now)
		redis.call('expire', key, 60)
		return 0
	`)

	nowSec := float64(time.Now().UnixNano()) / 1e9
	result, err := script.Run(ctx, tb.rdb, []string{fullKey}, tb.rate, tb.burst, nowSec).Int()
	if err != nil {
		return false, fmt.Errorf("rate limit check: %w", err)
	}

	return result == 1, nil
}

// Wait blocks until a token is available for the given key.
func (tb *TokenBucket) Wait(ctx context.Context, key string) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		allowed, err := tb.Allow(ctx, key)
		if err != nil {
			return err
		}
		if allowed {
			return nil
		}

		// Wait proportional to token refill rate
		waitTime := time.Duration(float64(time.Second) / tb.rate)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(waitTime):
		}
	}
}

// AdaptiveRateLimiter adjusts rate based on response codes.
type AdaptiveRateLimiter struct {
	tb     *TokenBucket
	minRPS float64
	maxRPS float64
	mu     sync.Mutex
}

// NewAdaptive creates an adaptive rate limiter.
func NewAdaptive(rdb *redis.Client, keyPrefix string, initialRPS float64, minRPS, maxRPS float64, burst int) *AdaptiveRateLimiter {
	return &AdaptiveRateLimiter{
		tb:     New(rdb, keyPrefix, initialRPS, burst),
		minRPS: minRPS,
		maxRPS: maxRPS,
	}
}

// Allow checks if a request is allowed.
func (a *AdaptiveRateLimiter) Allow(ctx context.Context, key string) (bool, error) {
	return a.tb.Allow(ctx, key)
}

// Wait blocks until allowed.
func (a *AdaptiveRateLimiter) Wait(ctx context.Context, key string) error {
	return a.tb.Wait(ctx, key)
}

// RecordResponse adjusts rate based on target response.
func (a *AdaptiveRateLimiter) RecordResponse(statusCode int) {
	a.mu.Lock()
	defer a.mu.Unlock()

	switch {
	case statusCode == 429:
		// Rate limited - reduce by 50%
		newRate := a.tb.rate * 0.5
		if newRate < a.minRPS {
			newRate = a.minRPS
		}
		a.tb.rate = newRate
		log.Warn().Float64("new_rps", newRate).Msg("rate limited, reducing speed")

	case statusCode >= 500:
		// Server error - reduce by 25%
		newRate := a.tb.rate * 0.75
		if newRate < a.minRPS {
			newRate = a.minRPS
		}
		a.tb.rate = newRate

	case statusCode >= 200 && statusCode < 400:
		// Success - slowly increase by 5%
		newRate := a.tb.rate * 1.05
		if newRate > a.maxRPS {
			newRate = a.maxRPS
		}
		a.tb.rate = newRate
	}
}
